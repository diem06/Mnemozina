"""
Amnezia VPN Web Panel
Веб-панель управления контейнерами Amnezia VPN на VPS через SSH.
"""
from __future__ import annotations

import re
import uuid
import threading

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
)

from config import Config
from ssh_manager import SSHSession, SSHError
from container_manager import ContainerManager

app = Flask(__name__)
app.config.from_object(Config)

_connections: dict[str, SSHSession] = {}
_connections_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _get_sid() -> str:
    if "sid" not in session:
        session["sid"] = str(uuid.uuid4())
    return session["sid"]


def _get_connection() -> SSHSession | None:
    sid = _get_sid()
    with _connections_lock:
        return _connections.get(sid)


def _set_connection(conn: SSHSession) -> None:
    sid = _get_sid()
    with _connections_lock:
        _connections[sid] = conn


def _clear_connection() -> None:
    sid = _get_sid()
    with _connections_lock:
        conn = _connections.pop(sid, None)
    if conn:
        conn.close()


def _require_connection() -> SSHSession | None:
    conn = _get_connection()
    if conn is None:
        return None
    if not conn.is_alive():
        _clear_connection()
        return None
    return conn


def _parse_port(raw: str) -> int | None:
    try:
        port = int(raw)
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


CONTAINER_NAME_RE = re.compile(r"amnezia-[a-z0-9-]{1,40}")


def _manager(conn: SSHSession) -> ContainerManager:
    return ContainerManager(
        conn,
        timeout=app.config["DOCKER_CMD_TIMEOUT"],
        install_timeout=app.config["CONTAINER_INSTALL_TIMEOUT"],
        primary_dns=app.config["PRIMARY_DNS"],
        secondary_dns=app.config["SECONDARY_DNS"],
        amnezia_dns_ip=app.config["AMNEZIA_DNS_IP"],
    )


def _is_allowed_container(name: str) -> bool:
    """Управлять разрешено только контейнерами amnezia-*."""
    return bool(CONTAINER_NAME_RE.fullmatch(name))


def _container_info(conn: SSHSession) -> list[dict]:
    code, out, err = conn.run(
        f"{conn.docker} ps -a --format '{{{{.Names}}}}|{{{{.Status}}}}|{{{{.ID}}}}|{{{{.Image}}}}'",
        timeout=app.config["DOCKER_CMD_TIMEOUT"],
    )
    if code != 0:
        raise SSHError(err.strip() or "Не удалось получить список контейнеров")

    existing: dict[str, dict] = {}
    for line in out.strip().splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) != 4:
            continue
        name, status, cid, image = parts
        existing[name] = {"status": status, "id": cid[:12], "image": image}

    # Сначала известные контейнеры, потом любые другие amnezia-* с сервера
    names = list(app.config["AMNEZIA_CONTAINERS"])
    names += sorted(n for n in existing if _is_allowed_container(n) and n not in names)

    labels = app.config["CONTAINER_LABELS"]
    result = []
    for name in names:
        info = existing.get(name)
        result.append({
            "name": name,
            "label": labels.get(name, name),
            "status": info["status"] if info else "не создан",
            "id": info["id"] if info else "—",
            "image": info["image"] if info else "",
            "running": bool(info) and info["status"].startswith("Up"),
            "exists": bool(info),
            "supports_clients": name in app.config["CLIENT_PROTOCOLS"],
        })
    # Несозданные — в конец, чтобы реальные контейнеры были сверху
    result.sort(key=lambda c: not c["exists"])
    return result


@app.context_processor
def inject_config():
    return {"config": app.config}


# ---------------------------------------------------------------------------
# Роуты: подключение
# ---------------------------------------------------------------------------

@app.route("/login")
def login():
    conn = _get_connection()
    if conn is not None:
        return redirect(url_for("index"))
    return render_template("login.html", prefill={})


@app.route("/connect", methods=["POST"])
def connect():
    host = request.form.get("host", "").strip()
    port_raw = request.form.get("port", "22").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    errors: list[str] = []
    if not host:
        errors.append("Укажите адрес сервера")
    if not username:
        errors.append("Укажите логин")
    if not password:
        errors.append("Укажите пароль")

    port = _parse_port(port_raw)
    if port is None:
        errors.append("Некорректный SSH-порт")

    if errors:
        for message in errors:
            flash(message, "error")
        return render_template("login.html", prefill={
            "host": host, "port": port_raw, "username": username,
        })

    assert port is not None

    conn = SSHSession(
        host=host,
        port=port,
        username=username,
        password=password,
        timeout=app.config["SSH_TIMEOUT"],
    )

    try:
        conn.connect()
        code, out, err = conn.run(f"{conn.docker} ps --format '{{{{.Names}}}}'")
        if code != 0:
            conn.close()
            flash(
                "SSH-подключение успешно, но Docker недоступен. "
                f"Ответ сервера: {err.strip() or out.strip()}",
                "error",
            )
            return render_template("login.html", prefill={
                "host": host, "port": port_raw, "username": username,
            })
    except SSHError as exc:
        flash(str(exc), "error")
        return render_template("login.html", prefill={
            "host": host, "port": port_raw, "username": username,
        })

    _clear_connection()
    _set_connection(conn)
    flash(f"Подключено к {host}", "ok")
    return redirect(url_for("index"))


@app.route("/disconnect")
def disconnect():
    _clear_connection()
    flash("Соединение закрыто", "ok")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Роуты: контейнеры
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    conn = _require_connection()
    if conn is None:
        flash("Необходимо подключиться к серверу", "error")
        return redirect(url_for("login"))

    try:
        containers = _container_info(conn)
    except SSHError as exc:
        flash(f"Соединение потеряно: {exc}", "error")
        _clear_connection()
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        containers=containers,
        host=conn.host,
        username=conn.username,
    )


@app.route("/action/<container_name>/<action>", methods=["POST"])
def container_action(container_name: str, action: str):
    conn = _require_connection()
    if conn is None:
        flash("Необходимо подключиться к серверу", "error")
        return redirect(url_for("login"))

    allowed_actions = {"start", "stop", "restart"}
    if action not in allowed_actions:
        flash("Недопустимое действие", "error")
        return redirect(url_for("index"))

    if not _is_allowed_container(container_name):
        flash("Контейнер не в списке разрешённых", "error")
        return redirect(url_for("index"))

    action_ru = {
        "start": "запуск", "stop": "остановка", "restart": "перезапуск"
    }[action]

    try:
        code, out, err = conn.run(
            f"{conn.docker} {action} {container_name}",
            timeout=app.config["DOCKER_CMD_TIMEOUT"],
        )
    except SSHError as exc:
        flash(f"Ошибка соединения: {exc}", "error")
        _clear_connection()
        return redirect(url_for("login"))

    label = app.config["CONTAINER_LABELS"].get(container_name, container_name)

    if code != 0:
        flash(
            f"{label}: ошибка при выполнении «{action_ru}» — "
            f"{err.strip() or out.strip()}",
            "error",
        )
    else:
        flash(f"{label}: {action_ru} выполнена успешно", "ok")

    return redirect(url_for("index"))


@app.route("/logs/<container_name>")
def container_logs(container_name: str):
    conn = _require_connection()
    if conn is None:
        return jsonify({"error": "Нет соединения"}), 401

    if not _is_allowed_container(container_name):
        return jsonify({"error": "Контейнер не разрешён"}), 403

    try:
        code, out, err = conn.run(
            f"{conn.docker} logs --tail 200 {container_name} 2>&1",
            timeout=app.config["DOCKER_CMD_TIMEOUT"],
        )
    except SSHError as exc:
        return jsonify({"error": str(exc)}), 500

    if code != 0 and not out:
        return jsonify({"error": err.strip() or "Не удалось получить логи"}), 500

    return jsonify({"logs": out})


# ---------------------------------------------------------------------------
# Роуты: создание контейнера
# ---------------------------------------------------------------------------

@app.route("/create", methods=["GET", "POST"])
def create_container():
    conn = _require_connection()
    if conn is None:
        flash("Необходимо подключиться к серверу", "error")
        return redirect(url_for("login"))

    creatable = app.config["CREATABLE_PROTOCOLS"]

    if request.method == "GET":
        return render_template("create_container.html", protocols=creatable)

    protocol = request.form.get("protocol", "").strip()
    if protocol not in creatable:
        flash("Неизвестный протокол", "error")
        return redirect(url_for("create_container"))

    meta = creatable[protocol]
    port_raw = request.form.get("port", "").strip() or str(meta["default_port"])
    try:
        port = int(port_raw)
    except ValueError:
        flash("Некорректный порт", "error")
        return redirect(url_for("create_container"))

    if not (1 <= port <= 65535):
        flash("Порт должен быть в диапазоне 1..65535", "error")
        return redirect(url_for("create_container"))

    manager = _manager(conn)
    try:
        result = manager.create_container(protocol, port)
    except SSHError as exc:
        flash(f"Ошибка соединения: {exc}", "error")
        _clear_connection()
        return redirect(url_for("login"))

    if result.get("ok"):
        flash(f"Контейнер {result['container']} создан и запущен", "ok")
    else:
        flash(f"Ошибка: {result.get('error', 'неизвестная')}", "error")

    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Роуты: клиенты
# ---------------------------------------------------------------------------

@app.route("/clients/<container_name>")
def list_clients(container_name: str):
    conn = _require_connection()
    if conn is None:
        flash("Необходимо подключиться к серверу", "error")
        return redirect(url_for("login"))

    if not _is_allowed_container(container_name):
        flash("Контейнер не в списке разрешённых", "error")
        return redirect(url_for("index"))

    manager = _manager(conn)
    try:
        result = manager.list_clients(container_name)
    except SSHError as exc:
        flash(f"Ошибка соединения: {exc}", "error")
        _clear_connection()
        return redirect(url_for("login"))

    if not result["ok"]:
        flash(result.get("error") or "Не удалось получить клиентов", "error")
        return redirect(url_for("index"))

    return render_template(
        "clients.html",
        container_name=container_name,
        container_label=app.config["CONTAINER_LABELS"].get(
            container_name, container_name
        ),
        clients=result["clients"],
        supports_clients=container_name in app.config["CLIENT_PROTOCOLS"],
    )


@app.route("/clients/<container_name>/add", methods=["POST"])
def add_client(container_name: str):
    conn = _require_connection()
    if conn is None:
        flash("Необходимо подключиться к серверу", "error")
        return redirect(url_for("login"))

    if not _is_allowed_container(container_name):
        flash("Контейнер не в списке разрешённых", "error")
        return redirect(url_for("index"))

    client_name = request.form.get("client_name", "").strip()
    if not client_name:
        flash("Укажите имя клиента", "error")
        return redirect(url_for("list_clients", container_name=container_name))

    manager = _manager(conn)
    try:
        result = manager.add_client(container_name, client_name)
    except SSHError as exc:
        flash(f"Ошибка соединения: {exc}", "error")
        _clear_connection()
        return redirect(url_for("login"))

    if not result["ok"]:
        flash(
            f"Ошибка: {result.get('error') or 'не удалось создать клиента'}",
            "error",
        )
        return redirect(url_for("list_clients", container_name=container_name))

    return render_template(
        "client_config.html",
        container_name=container_name,
        container_label=app.config["CONTAINER_LABELS"].get(
            container_name, container_name
        ),
        client_name=result["client"],
        config=result["config"],
        filename=result.get("filename", "client.conf"),
    )


@app.route("/clients/<container_name>/delete", methods=["POST"])
def delete_client(container_name: str):
    conn = _require_connection()
    if conn is None:
        flash("Необходимо подключиться к серверу", "error")
        return redirect(url_for("login"))

    if not _is_allowed_container(container_name):
        flash("Контейнер не в списке разрешённых", "error")
        return redirect(url_for("index"))

    # clientId (публичный ключ WG / CN OpenVPN / UUID XRay) передаём в теле
    # формы: в base64-ключах WireGuard бывают "/" и "+", в URL они ломаются.
    client_id = request.form.get("client_id", "").strip()
    client_name = request.form.get("client_name", client_id)

    manager = _manager(conn)
    try:
        result = manager.delete_client(container_name, client_id)
    except SSHError as exc:
        flash(f"Ошибка соединения: {exc}", "error")
        _clear_connection()
        return redirect(url_for("login"))

    if result["ok"]:
        flash(f"Клиент {client_name} удалён", "ok")
    else:
        flash(f"Ошибка: {result.get('error')}", "error")

    return redirect(url_for("list_clients", container_name=container_name))


@app.errorhandler(404)
def not_found(_error):
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Запуск
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)