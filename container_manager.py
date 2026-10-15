"""
Управление контейнерами Amnezia VPN и клиентами внутри них.

Все пути, имена контейнеров и форматы файлов повторяют amnezia-client
(https://github.com/amnezia-vpn/amnezia-client):

* AmneziaWG 2 / 3.1  -> контейнер amnezia-awg2, /opt/amnezia/awg/awg0.conf, бинарь awg, интерфейс awg0
* AmneziaWG legacy   -> контейнер amnezia-awg,  /opt/amnezia/awg/wg0.conf,   бинарь wg,  интерфейс wg0
* WireGuard          -> контейнер amnezia-wireguard, /opt/amnezia/wireguard/wg0.conf
* OpenVPN            -> контейнер amnezia-openvpn, /opt/amnezia/openvpn (easyrsa, pki/)
* XRay               -> контейнер amnezia-xray, /opt/amnezia/xray/server.json

Список пользователей хранится в /opt/amnezia/<type>/clientsTable (JSON-массив
{"clientId": ..., "userData": {"clientName": ..., "creationDate": ...}}) —
так его ведёт приложение AmneziaVPN, поэтому имена клиентов совпадают в обоих.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import secrets
import shlex
import string
import time
import uuid as uuid_module
from urllib.parse import quote, urlencode

from ssh_manager import SSHSession, SSHError
from connection_settings import (
    apply_ipsec_dns,
    apply_wg_settings,
    apply_xray_settings,
    default_xray_server,
    ipsec_form_values,
    openvpn_form_values,
    parse_wg_conf as _parse_wg_conf,
    render_openvpn_conf,
    settings_form,
    wg_form_values,
    xray_form_values,
)

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_scripts")

# ---------------------------------------------------------------------------
# Профили контейнеров
# ---------------------------------------------------------------------------

WG_PROFILES = {
    "amnezia-awg2": {
        "bin": "awg", "iface": "awg0", "awg": True,
        "dir": "/opt/amnezia/awg",
        "conf": "/opt/amnezia/awg/awg0.conf",
    },
    "amnezia-awg": {  # legacy AWG: образ amneziavpn/amnezia-wg, бинарь называется wg
        "bin": "wg", "iface": "wg0", "awg": True,
        "dir": "/opt/amnezia/awg",
        "conf": "/opt/amnezia/awg/wg0.conf",
    },
    "amnezia-wireguard": {
        "bin": "wg", "iface": "wg0", "awg": False,
        "dir": "/opt/amnezia/wireguard",
        "conf": "/opt/amnezia/wireguard/wg0.conf",
    },
}

OPENVPN_DIR = "/opt/amnezia/openvpn"
XRAY_DIR = "/opt/amnezia/xray"
XRAY_SERVER_CONFIG = f"{XRAY_DIR}/server.json"

# Порядок AWG-параметров в клиентском шаблоне (server_scripts/awg/template.conf)
AWG_CLIENT_KEYS = [
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5",
    "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
    "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
]
# Наличие любого из них = AmneziaWG 3.1 (awgProtocolConfig.cpp::hasAwg3Markers)
AWG3_MARKERS = [
    "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
    "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
]

DEFAULT_MTU = "1376"
AWG_DEFAULT_SPECIAL_JUNK_1 = (
    "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
)

CLIENT_NAME_MAX = 64


def _now_str() -> str:
    # Формат QDateTime::toString() по умолчанию, как пишет amnezia-client
    return time.strftime("%a %b %d %H:%M:%S %Y")


def _random_id(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class ContainerManager:
    """Операции с контейнерами и клиентами Amnezia."""

    def __init__(
        self,
        ssh: SSHSession,
        timeout: int = 60,
        install_timeout: int = 900,
        primary_dns: str = "1.1.1.1",
        secondary_dns: str = "1.0.0.1",
        amnezia_dns_ip: str = "172.29.172.254",
    ):
        self.ssh = ssh
        self.timeout = timeout
        self.install_timeout = install_timeout
        self.docker = getattr(ssh, "docker", "docker")
        self.primary_dns = primary_dns
        self.secondary_dns = secondary_dns
        self.amnezia_dns_ip = amnezia_dns_ip

    # ------------------------------------------------------------------
    # Низкоуровневые утилиты
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_container(name: str) -> bool:
        return bool(re.fullmatch(r"amnezia-[a-z0-9-]{1,40}", name))

    @staticmethod
    def validate_client_name(name: str) -> bool:
        if not name or len(name) > CLIENT_NAME_MAX:
            return False
        return not any(ord(ch) < 32 for ch in name)

    def _exec(self, container: str, args: str, input_data: str | None = None,
              timeout: int | None = None):
        """docker exec -i <container> <args>"""
        return self.ssh.run(
            f"{self.docker} exec -i {container} {args}",
            timeout=timeout or self.timeout,
            input_data=input_data,
        )

    def _script(self, container: str, script: str, shell: str = "bash",
                timeout: int | None = None):
        """Выполняет скрипт внутри контейнера, передавая его через stdin."""
        return self._exec(container, f"{shell} -s", input_data=script, timeout=timeout)

    def _read(self, container: str, path: str) -> str:
        code, out, _ = self._exec(container, f"cat {shlex.quote(path)}")
        return out if code == 0 else ""

    def _read_json(self, container: str, path: str) -> dict:
        raw = self._read(container, path)
        if not raw.strip():
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, container: str, path: str, data: str, append: bool = False) -> None:
        op = ">>" if append else ">"
        code, out, err = self._exec(
            container, f"sh -c {shlex.quote(f'cat {op} {shlex.quote(path)}')}", input_data=data
        )
        if code != 0:
            raise SSHError(err.strip() or out.strip() or f"Не удалось записать {path}")

    def container_exists(self, name: str) -> bool:
        code, out, _ = self.ssh.run(
            f"{self.docker} ps -a --format '{{{{.Names}}}}'", timeout=self.timeout
        )
        return name in out.split()

    def container_running(self, name: str) -> bool:
        code, out, _ = self.ssh.run(
            f"{self.docker} inspect -f '{{{{.State.Running}}}}' {name} 2>/dev/null || true",
            timeout=self.timeout,
        )
        return out.strip() == "true"

    def _server_host(self) -> str:
        # amnezia-client в Endpoint пишет адрес, по которому подключались по SSH
        # (credentials.hostName), а не внутренний IP из hostname -I.
        return self.ssh.host

    def _dns(self) -> tuple[str, str]:
        if self.container_running("amnezia-dns"):
            return self.amnezia_dns_ip, self.secondary_dns
        return self.primary_dns, self.secondary_dns

    @staticmethod
    def protocol_of(container: str) -> str:
        if container in WG_PROFILES:
            return "wireguard"
        if container == "amnezia-openvpn":
            return "openvpn"
        if container == "amnezia-xray":
            return "xray"
        return "unknown"

    # ------------------------------------------------------------------
    # clientsTable (общий с приложением AmneziaVPN)
    # ------------------------------------------------------------------

    def _table_path(self, container: str) -> str:
        if container in WG_PROFILES:
            return f"{WG_PROFILES[container]['dir']}/clientsTable"
        if container == "amnezia-openvpn":
            return f"{OPENVPN_DIR}/clientsTable"
        if container == "amnezia-xray":
            return f"{XRAY_DIR}/clientsTable"
        raise ValueError(container)

    def _load_table(self, container: str) -> list[dict]:
        raw = self._read(container, self._table_path(container)).strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            # старый формат: {"<clientId>": {"clientName": ...}}
            return [
                {"clientId": cid, "userData": {"clientName": (v or {}).get("clientName", "")}}
                for cid, v in data.items()
            ]
        return [x for x in data if isinstance(x, dict) and x.get("clientId")]

    def _save_table(self, container: str, table: list[dict]) -> None:
        self._write(container, self._table_path(container), json.dumps(table, indent=4, ensure_ascii=False))

    def _table_add(self, container: str, client_id: str, client_name: str) -> None:
        table = self._load_table(container)
        for item in table:
            if item.get("clientId") == client_id:
                item.setdefault("userData", {})["clientName"] = client_name
                item["userData"]["creationDate"] = _now_str()
                break
        else:
            table.append({
                "clientId": client_id,
                "userData": {"clientName": client_name, "creationDate": _now_str()},
            })
        self._save_table(container, table)

    def _table_remove(self, container: str, client_id: str) -> None:
        table = self._load_table(container)
        new_table = [x for x in table if x.get("clientId") != client_id]
        if len(new_table) != len(table):
            self._save_table(container, new_table)

    @staticmethod
    def _merge(table: list[dict], ids: list[str], extra: dict[str, dict] | None = None,
               hidden: set[str] | None = None) -> list[dict]:
        """
        Склеивает clientsTable с фактическим списком клиентов на сервере.
        Клиенты, которых нет в таблице (созданы вручную/старой панелью),
        получают имя "Client N", как в amnezia-client.
        """
        extra = extra or {}
        hidden = hidden or set()
        known = {x["clientId"]: x for x in table}
        result = []
        counter = 0
        for cid in ids:
            if cid in hidden:
                continue
            entry = known.get(cid)
            user = (entry or {}).get("userData", {})
            name = user.get("clientName", "")
            created = user.get("creationDate", "")
            if not name:
                name = f"Client {counter}"
                counter += 1
            item = {"id": cid, "name": name, "created": created, "in_table": bool(entry)}
            item.update(extra.get(cid, {}))
            result.append(item)
        return result

    # ------------------------------------------------------------------
    # Список клиентов
    # ------------------------------------------------------------------

    def list_clients(self, container: str) -> dict:
        """Возвращает {"ok": bool, "clients": [...], "error": str|None}."""
        if not self._validate_container(container):
            return {"ok": False, "clients": [], "error": "Некорректное имя контейнера"}
        protocol = self.protocol_of(container)
        try:
            if not self.container_running(container):
                return {"ok": False, "clients": [], "error": f"Контейнер {container} не запущен"}
            if protocol == "wireguard":
                clients = self._list_wg_clients(container)
            elif protocol == "openvpn":
                clients = self._list_openvpn_clients(container)
            elif protocol == "xray":
                clients = self._list_xray_clients(container)
            else:
                return {"ok": False, "clients": [], "error": "Протокол не поддерживает клиентов"}
        except SSHError as exc:
            return {"ok": False, "clients": [], "error": str(exc)}
        return {"ok": True, "clients": clients, "error": None}

    def _wg_show(self, container: str) -> dict[str, dict]:
        prof = WG_PROFILES[container]
        code, out, _ = self._exec(container, f"{prof['bin']} show {prof['iface']}")
        stats: dict[str, dict] = {}
        current = None
        for raw in out.splitlines():
            line = raw.strip()
            if line.startswith("peer:"):
                current = line.split(":", 1)[1].strip()
                stats[current] = {}
            elif current and ":" in line:
                key, value = (p.strip() for p in line.split(":", 1))
                if key == "latest handshake":
                    stats[current]["handshake"] = value.replace(" ago", "")
                elif key == "transfer":
                    # "1.2 MiB received, 3.4 MiB sent" — с точки зрения сервера
                    parts = [p.strip() for p in value.split(",")]
                    if len(parts) == 2:
                        stats[current]["upload"] = parts[0].replace(" received", "")
                        stats[current]["download"] = parts[1].replace(" sent", "")
                elif key == "allowed ips":
                    stats[current]["allowed_ips"] = value
                elif key == "endpoint":
                    stats[current]["endpoint"] = value
        return stats

    def _list_wg_clients(self, container: str) -> list[dict]:
        prof = WG_PROFILES[container]
        conf = self._read(container, prof["conf"])
        if not conf.strip():
            raise SSHError(f"Не найден конфиг сервера {prof['conf']} в контейнере {container}")
        _, peers = _parse_wg_conf(conf)
        ids = [p["PublicKey"] for p in peers if p.get("PublicKey")]
        extra = {p["PublicKey"]: {"allowed_ips": p.get("AllowedIPs", "")} for p in peers if p.get("PublicKey")}
        for pub, st in self._wg_show(container).items():
            extra.setdefault(pub, {}).update(st)
        return self._merge(self._load_table(container), ids, extra)

    def _list_openvpn_clients(self, container: str) -> list[dict]:
        code, out, _ = self._exec(container, f"ls {OPENVPN_DIR}/pki/issued")
        ids = []
        for name in out.split():
            if name.endswith(".crt") and name not in ("AmneziaReq.crt", "server.crt"):
                ids.append(name[:-4])
        # отозванные сертификаты остаются в issued только до revoke, так что ок
        return self._merge(self._load_table(container), ids)

    def _xray_config(self, container: str) -> dict:
        raw = self._read(container, XRAY_SERVER_CONFIG)
        if not raw.strip():
            raise SSHError(f"Не найден {XRAY_SERVER_CONFIG} в контейнере {container}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SSHError(f"Не удалось разобрать {XRAY_SERVER_CONFIG}: {exc}") from exc

    def _xray_inbound(self, config: dict) -> dict:
        """Return the VLESS inbound, preferring Reality over unrelated inbounds."""
        inbounds = config.get("inbounds") or []
        candidates = [i for i in inbounds if i.get("protocol", "vless") == "vless"]
        candidates = candidates or inbounds
        reality = [i for i in candidates if i.get("streamSettings", {}).get("security") == "reality"]
        if reality:
            return reality[0]
        if candidates:
            return candidates[0]
        raise SSHError("В конфиге XRay нет inbounds")

    def _xray_link(self, container: str, inbound: dict, client_id: str,
                   client_name: str = "Client") -> str:
        """Build a VLESS link from the actual inbound stream settings."""
        stream = inbound.get("streamSettings", {}) or {}
        network = str(stream.get("network", "tcp"))
        security = str(stream.get("security", "none"))
        params = {"type": network, "security": security, "encryption": "none"}
        # flow is valid only for TCP/RAW. Existing bad flow values are ignored.
        client = next((c for c in inbound.get("settings", {}).get("clients", [])
                       if c.get("id") == client_id), {})
        if network in ("tcp", "raw") and client.get("flow"):
            params["flow"] = client["flow"]
        reality = stream.get("realitySettings", {}) or {}
        if security == "reality":
            pbk = self._read(container, f"{XRAY_DIR}/xray_public.key").strip()
            sid = self._read(container, f"{XRAY_DIR}/xray_short_id.key").strip()
            params.update({
                "sni": (reality.get("serverNames") or [""])[0],
                "fp": (reality.get("fingerprint") or "chrome"),
                "pbk": pbk,
                "sid": sid or (reality.get("shortIds") or [""])[0],
            })
        sock = stream.get("xhttpSettings", {}) or {}
        if network == "xhttp":
            params["path"] = sock.get("path") or "/"
            params["mode"] = sock.get("mode") or "auto"
            if sock.get("host"):
                params["host"] = sock["host"]
        elif network == "ws":
            ws = stream.get("wsSettings", {}) or {}
            params["path"] = ws.get("path") or "/"
            headers = ws.get("headers", {}) or {}
            if headers.get("Host") or headers.get("host"):
                params["host"] = headers.get("Host") or headers.get("host")
        elif network == "grpc":
            grpc = stream.get("grpcSettings", {}) or {}
            if grpc.get("serviceName"):
                params["serviceName"] = grpc["serviceName"]
        query = urlencode(params, quote_via=quote)
        return (f"vless://{quote(str(client_id), safe='')}@{self._server_host()}"
                f":{inbound.get('port', 443)}?{query}#{quote(client_name, safe='')}")

    def _list_xray_clients(self, container: str) -> list[dict]:
        config = self._xray_config(container)
        inbound = self._xray_inbound(config)
        clients = inbound.get("settings", {}).get("clients", [])
        ids = [c.get("id") for c in clients if c.get("id")]
        own = self._read(container, f"{XRAY_DIR}/xray_uuid.key").strip()
        extra = {own: {"name_hint": "основной конфиг"}} if own else {}
        return self._merge(self._load_table(container), ids, extra)

    # ------------------------------------------------------------------
    # Создание клиента
    # ------------------------------------------------------------------

    def add_client(self, container: str, client_name: str) -> dict:
        """
        Создаёт клиента. Возвращает:
        {"ok": bool, "client": str, "config": str, "filename": str, "error": str|None}
        """
        fail = lambda msg: {"ok": False, "client": client_name, "config": "", "error": msg}  # noqa: E731
        if not self._validate_container(container):
            return fail("Некорректное имя контейнера")
        if not self.validate_client_name(client_name):
            return fail(f"Имя клиента: от 1 до {CLIENT_NAME_MAX} символов")

        protocol = self.protocol_of(container)
        try:
            if not self.container_running(container):
                return fail(f"Контейнер {container} не запущен")
            if protocol == "wireguard":
                return self._add_wg_client(container, client_name)
            if protocol == "openvpn":
                return self._add_openvpn_client(container, client_name)
            if protocol == "xray":
                return self._add_xray_client(container, client_name)
        except SSHError as exc:
            return fail(str(exc))
        return fail(f"Протокол {protocol} не поддерживает клиентов")

    def _apply_xray_config(self, container: str, config: dict, backup: str) -> None:
        """Validate, atomically install, restart, verify; restore on any failure."""
        serialized = json.dumps(config, indent=4, ensure_ascii=False) + "\n"
        temp = XRAY_SERVER_CONFIG + ".new.json"
        self._write(container, temp, serialized)
        # Resolve the binary inside the same container; installations differ by image.
        test = ("bin=$(command -v xray 2>/dev/null || find /usr/local/bin /usr/bin /opt -type f -name xray 2>/dev/null | head -1); "
                "[ -n \"$bin\" ] || { echo 'xray binary not found' >&2; exit 127; }; "
                f"$bin run -test -format json -c {shlex.quote(temp)}")
        code, out, err = self._exec(container, f"sh -c {shlex.quote(test)}", timeout=self.install_timeout)
        if code != 0:
            raise SSHError(err.strip() or out.strip() or "Проверка конфигурации XRay не пройдена")
        self._write(container, XRAY_SERVER_CONFIG + ".bak", backup)
        try:
            mv = f"mv {shlex.quote(temp)} {shlex.quote(XRAY_SERVER_CONFIG)}"
            code, out, err = self._exec(container, f"sh -c {shlex.quote(mv)}")
            if code != 0:
                raise SSHError(err.strip() or out.strip() or "Не удалось установить конфиг XRay")
            code, out, err = self.ssh.run(f"{self.docker} restart {container}", timeout=self.install_timeout)
            if code != 0 or not self._xray_process_running(container):
                raise SSHError(err.strip() or out.strip() or "XRay не запустился после обновления")
        except SSHError:
            self._write(container, XRAY_SERVER_CONFIG, backup)
            self.ssh.run(f"{self.docker} restart {container}", timeout=self.install_timeout)
            raise

    def _xray_process_running(self, container: str) -> bool:
        code, out, _ = self._exec(container, "sh -c 'pgrep -x xray >/dev/null || pidof xray >/dev/null'")
        return code == 0

    def _gen_wg_keys(self, container: str) -> tuple[str, str]:
        prof = WG_PROFILES[container]
        code, priv, err = self._exec(container, f"{prof['bin']} genkey")
        priv = priv.strip()
        if code != 0 or not priv:
            raise SSHError(f"Не удалось сгенерировать ключ: {err.strip()}")
        code, pub, err = self._exec(container, f"{prof['bin']} pubkey", input_data=priv + "\n")
        pub = pub.strip()
        if code != 0 or not pub:
            raise SSHError(f"Не удалось получить публичный ключ: {err.strip()}")
        return priv, pub

    @staticmethod
    def _next_ip(interface: dict, peers: list[dict]) -> str:
        address = (interface.get("Address") or "10.8.1.0/24").split(",")[0].strip()
        net = ipaddress.ip_interface(address).network
        used = {ipaddress.ip_interface(address).ip}
        for peer in peers:
            for item in peer.get("AllowedIPs", "").split(","):
                item = item.strip()
                if not item:
                    continue
                try:
                    used.add(ipaddress.ip_interface(item).ip)
                except ValueError:
                    pass
        # У amnezia-client сервер имеет Address = 10.8.1.0/24, клиенты начинаются с .1
        for host in net.hosts():
            if host not in used:
                return str(host)
        raise SSHError(f"В подсети {net} закончились свободные адреса")

    def _add_wg_client(self, container: str, client_name: str) -> dict:
        prof = WG_PROFILES[container]
        conf = self._read(container, prof["conf"])
        if not conf.strip():
            raise SSHError(f"Не найден конфиг сервера {prof['conf']} в контейнере {container}")
        interface, peers = _parse_wg_conf(conf)

        priv, pub = self._gen_wg_keys(container)
        client_ip = self._next_ip(interface, peers)

        server_pub = self._read(container, f"{prof['dir']}/wireguard_server_public_key.key").strip()
        if not server_pub and interface.get("PrivateKey"):
            _, server_pub, _ = self._exec(container, f"{prof['bin']} pubkey",
                                          input_data=interface["PrivateKey"] + "\n")
            server_pub = server_pub.strip()
        if not server_pub:
            raise SSHError("Не удалось получить публичный ключ сервера")
        psk = self._read(container, f"{prof['dir']}/wireguard_psk.key").strip()

        # 1. Дописываем peer в конфиг сервера (как WireguardConfigurator)
        peer = "\n[Peer]\nPublicKey = {}\n{}AllowedIPs = {}/32\n".format(
            pub, f"PresharedKey = {psk}\n" if psk else "", client_ip
        )
        self._write(container, prof["conf"], peer, append=True)

        # 2. Применяем без разрыва соединений; при неудаче — рестарт контейнера
        bin_, iface, path = prof["bin"], prof["iface"], prof["conf"]
        code, out, err = self._script(
            container, f"{bin_} syncconf {iface} <({bin_}-quick strip {path})\n"
        )
        if code != 0:
            self.ssh.run(f"{self.docker} restart {container}", timeout=self.install_timeout)

        # 3. Регистрируем в clientsTable — так клиента увидит и приложение AmneziaVPN
        self._table_add(container, pub, client_name)
        # Приватный ключ нужен, чтобы позже собрать ссылку и QR из списка клиентов.
        self._save_wg_secret(container, pub, priv)

        config_text = self._compose_wg_config(
            container, interface, priv, f"{client_ip}/32", server_pub, psk,
        )
        return {
            "ok": True, "client": client_name, "config": config_text,
            "filename": f"{self._safe_filename(client_name)}.conf", "error": None,
        }

    def _wg_secrets_path(self, container: str) -> str:
        return f"{WG_PROFILES[container]['dir']}/panel_client_secrets.json"

    def _load_wg_secrets(self, container: str) -> dict[str, str]:
        raw = self._read(container, self._wg_secrets_path(container)).strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(key): str(value) for key, value in data.items() if key and value}

    def _save_wg_secret(self, container: str, public_key: str, private_key: str) -> None:
        stored = self._load_wg_secrets(container)
        stored[public_key] = private_key
        self._write(
            container,
            self._wg_secrets_path(container),
            json.dumps(stored, indent=2) + "\n",
        )

    def _drop_wg_secret(self, container: str, public_key: str) -> None:
        stored = self._load_wg_secrets(container)
        if public_key not in stored:
            return
        del stored[public_key]
        self._write(
            container,
            self._wg_secrets_path(container),
            json.dumps(stored, indent=2) + "\n",
        )

    def _compose_wg_config(
        self,
        container: str,
        interface: dict,
        private_key: str,
        client_address: str,
        server_public: str,
        psk: str,
    ) -> str:
        prof = WG_PROFILES[container]
        if "/" not in client_address:
            client_address = f"{client_address}/32"
        port = interface.get("ListenPort") or "51820"
        dns1, dns2 = self._dns()
        lines = [
            "[Interface]",
            f"Address = {client_address}",
            f"DNS = {dns1}, {dns2}",
            f"PrivateKey = {private_key}",
        ]
        is_awg3 = False
        if prof["awg"]:
            for key in AWG_CLIENT_KEYS:
                value = interface.get(key, "").strip()
                if value and not value.startswith("$"):
                    lines.append(f"{key} = {value}")
            is_awg3 = any(interface.get(k) for k in AWG3_MARKERS) or \
                interface.get("RandomTrailers") == "on" or interface.get("DisableCookies") == "on"
        opts = self._read_json(container, f"{prof['dir']}/panel_client_opts.json")
        mtu = str(opts.get("mtu") or DEFAULT_MTU)
        lines.append(f"MTU = {mtu}")
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {server_public}",
        ]
        if psk:
            lines.append(f"PresharedKey = {psk}")
        lines += [
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"Endpoint = {self._server_host()}:{port}",
            f"PersistentKeepalive = {'25-35' if is_awg3 else '25'}",
            "",
        ]
        return "\n".join(lines)

    def _wg_client_config(self, container: str, client_id: str) -> str:
        prof = WG_PROFILES[container]
        conf = self._read(container, prof["conf"])
        if not conf.strip():
            raise SSHError(f"Не найден конфиг сервера {prof['conf']} в контейнере {container}")
        interface, peers = _parse_wg_conf(conf)
        peer = next((item for item in peers if item.get("PublicKey") == client_id), None)
        if peer is None:
            raise SSHError("Клиент не найден")
        private_key = self._load_wg_secrets(container).get(client_id, "")
        if not private_key:
            raise SSHError(
                "Приватный ключ этого клиента на сервере не сохранён. "
                "Ссылка и QR доступны для клиентов, созданных в этой версии панели."
            )
        server_pub = self._read(container, f"{prof['dir']}/wireguard_server_public_key.key").strip()
        if not server_pub and interface.get("PrivateKey"):
            _, server_pub, _ = self._exec(
                container, f"{prof['bin']} pubkey",
                input_data=interface["PrivateKey"] + "\n",
            )
            server_pub = server_pub.strip()
        if not server_pub:
            raise SSHError("Не удалось получить публичный ключ сервера")
        psk = (peer.get("PresharedKey") or "").strip() or \
            self._read(container, f"{prof['dir']}/wireguard_psk.key").strip()
        allowed = (peer.get("AllowedIPs") or "").split(",")[0].strip() or "10.8.1.1/32"
        return self._compose_wg_config(
            container, interface, private_key, allowed, server_pub, psk,
        )

    @staticmethod
    def _safe_filename(name: str) -> str:
        return re.sub(r"[^\w.\-]+", "_", name).strip("._") or "client"

    @staticmethod
    def _pem_only(text: str) -> str:
        idx = text.find("-----BEGIN")
        return (text[idx:] if idx >= 0 else text).strip()

    def _add_openvpn_client(self, container: str, client_name: str) -> dict:
        client_id = _random_id(32)
        code, out, err = self._script(
            container,
            f"cd {OPENVPN_DIR} && export EASYRSA_BATCH=1 && "
            f"easyrsa build-client-full {client_id} nopass\n",
            timeout=self.install_timeout,
        )
        if code != 0:
            raise SSHError(err.strip() or out.strip() or "Не удалось выпустить сертификат")

        self._table_add(container, client_id, client_name)
        return {
            "ok": True,
            "client": client_name,
            "config": self._openvpn_client_config(container, client_id),
            "filename": f"{self._safe_filename(client_name)}.ovpn",
            "error": None,
        }

    def _openvpn_client_config(self, container: str, client_id: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", client_id):
            raise SSHError("Некорректный идентификатор клиента")
        ca = self._pem_only(self._read(container, f"{OPENVPN_DIR}/pki/ca.crt"))
        cert = self._pem_only(self._read(container, f"{OPENVPN_DIR}/pki/issued/{client_id}.crt"))
        key = self._pem_only(self._read(container, f"{OPENVPN_DIR}/pki/private/{client_id}.key"))
        ta = "\n".join(
            line for line in self._read(container, f"{OPENVPN_DIR}/ta.key").splitlines()
            if not line.strip().startswith("#")
        ).strip()
        if not (ca and cert and key):
            raise SSHError("Не удалось прочитать сертификаты клиента")

        server_conf = self._read(container, f"{OPENVPN_DIR}/server.conf")
        opts: dict[str, str] = {}
        for line in server_conf.splitlines():
            parts = line.strip().split(None, 1)
            if parts:
                opts.setdefault(parts[0], parts[1] if len(parts) > 1 else "")
        _port_code, port_out, _ = self.ssh.run(
            f"{self.docker} port {container} 2>/dev/null | head -n1", timeout=self.timeout
        )
        match = re.search(r":(\d+)\s*$", port_out.strip())
        port = match.group(1) if match else opts.get("port", "1194")
        proto = opts.get("proto", "udp")
        dns1, dns2 = self._dns()

        client_opts = self._read_json(container, f"{OPENVPN_DIR}/panel_client_opts.json")
        cfg = [
            "client", "dev tun", f"proto {proto}", "resolv-retry infinite", "nobind",
            "persist-key", "persist-tun",
        ]
        if "ncp-disable" in opts:
            cfg.append("ncp-disable")
        cfg += [
            f"cipher {opts.get('cipher', 'AES-256-GCM')}",
            f"auth {opts.get('auth', 'SHA512')}",
            "verb 3", "tls-client", "tls-version-min 1.2", "key-direction 1",
            "remote-cert-tls server", "redirect-gateway def1 bypass-dhcp", "",
            f"dhcp-option DNS {dns1}", f"dhcp-option DNS {dns2}",
        ]
        if client_opts.get("block_outside_dns", True):
            cfg.append("block-outside-dns")
        extra = str(client_opts.get("additional_client") or "").strip()
        if extra:
            cfg += ["", extra]
        cfg += [
            "",
            f"remote {self._server_host()} {port}", "",
            "<ca>", ca, "</ca>", "<cert>", cert, "</cert>", "<key>", key, "</key>",
        ]
        if ta and "tls-auth" in opts:
            cfg += ["<tls-auth>", ta, "</tls-auth>"]
        return "\n".join(cfg) + "\n"

    def _add_xray_client(self, container: str, client_name: str) -> dict:
        config = self._xray_config(container)
        inbound = self._xray_inbound(config)
        stream = inbound.get("streamSettings", {}) or {}
        network = stream.get("network", "tcp")
        clients = inbound.setdefault("settings", {}).setdefault("clients", [])
        # Repair all legacy clients: vision flow is never valid for XHTTP/WS/gRPC.
        if network not in ("tcp", "raw"):
            for client in clients:
                client.pop("flow", None)
        client_id = str(uuid_module.uuid4())
        entry = {"id": client_id}
        if network in ("tcp", "raw"):
            entry["flow"] = "xtls-rprx-vision"
        clients.append(entry)
        backup = self._read(container, XRAY_SERVER_CONFIG)
        self._apply_xray_config(container, config, backup)
        self._table_add(container, client_id, client_name)
        return {
            "ok": True,
            "client": client_name,
            "config": self._xray_link(container, inbound, client_id, client_name),
            "filename": f"{self._safe_filename(client_name)}.txt",
            "error": None,
        }

    def edit_client(self, container: str, client_id: str, client_name: str) -> dict:
        """Изменяет отображаемое имя, не меняя протокольные ключи/идентификатор."""
        if not self._validate_container(container) or not client_id:
            return {"ok": False, "error": "Некорректные параметры клиента"}
        if not self.validate_client_name(client_name):
            return {"ok": False, "error": f"Имя клиента: от 1 до {CLIENT_NAME_MAX} символов"}
        table = self._load_table(container)
        found = False
        for item in table:
            if item.get("clientId") == client_id:
                item.setdefault("userData", {})["clientName"] = client_name
                found = True
                break
        if not found:
            table.append({
                "clientId": client_id,
                "userData": {"clientName": client_name, "creationDate": _now_str()},
            })
        self._save_table(container, table)
        return {"ok": True}

    def client_config(self, container: str, client_id: str, client_name: str = "Client") -> dict:
        """Ссылка или конфиг, которым клиент подключается. Его же кодирует QR."""
        fail = lambda msg: {"ok": False, "config": "", "link": "", "error": msg}  # noqa: E731
        if not self._validate_container(container) or not client_id:
            return fail("Некорректные параметры клиента")
        protocol = self.protocol_of(container)
        try:
            if not self.container_running(container):
                return fail(f"Контейнер {container} не запущен")
            if protocol == "wireguard":
                link = self._wg_client_config(container, client_id)
                filename = f"{self._safe_filename(client_name)}.conf"
            elif protocol == "openvpn":
                link = self._openvpn_client_config(container, client_id)
                filename = f"{self._safe_filename(client_name)}.ovpn"
            elif protocol == "xray":
                config = self._xray_config(container)
                inbound = self._xray_inbound(config)
                clients = inbound.get("settings", {}).get("clients", [])
                if not any(item.get("id") == client_id for item in clients):
                    return fail("Клиент не найден")
                link = self._xray_link(container, inbound, client_id, client_name)
                filename = f"{self._safe_filename(client_name)}.txt"
            else:
                return fail("Протокол не поддерживает ссылку подключения")
        except SSHError as exc:
            return fail(str(exc))
        return {
            "ok": True,
            "config": link,
            "link": link,
            "filename": filename,
            "error": None,
        }

    # ------------------------------------------------------------------
    # Удаление клиента
    # ------------------------------------------------------------------

    def delete_client(self, container: str, client_id: str) -> dict:
        if not self._validate_container(container):
            return {"ok": False, "error": "Некорректное имя контейнера"}
        if not client_id or not re.fullmatch(r"[A-Za-z0-9+/=_-]{1,128}", client_id):
            return {"ok": False, "error": "Некорректный идентификатор клиента"}
        protocol = self.protocol_of(container)
        try:
            if protocol == "wireguard":
                self._delete_wg_client(container, client_id)
            elif protocol == "openvpn":
                self._delete_openvpn_client(container, client_id)
            elif protocol == "xray":
                self._delete_xray_client(container, client_id)
            else:
                return {"ok": False, "error": "Протокол не поддерживает удаление клиентов"}
        except SSHError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def _delete_wg_client(self, container: str, client_id: str) -> None:
        prof = WG_PROFILES[container]
        conf = self._read(container, prof["conf"])
        if not conf.strip():
            raise SSHError(f"Не найден конфиг сервера {prof['conf']}")
        # Режем на секции по "[" и выкидываем [Peer] с нужным PublicKey
        blocks = re.split(r"(?m)^(?=\s*\[)", conf)
        kept = []
        for block in blocks:
            if block.strip().lower().startswith("[peer]"):
                _, peers = _parse_wg_conf(block)
                if peers and peers[0].get("PublicKey") == client_id:
                    continue
            kept.append(block)
        new_conf = "".join(kept).rstrip() + "\n"
        if new_conf != conf:
            self._write(container, prof["conf"], new_conf)
            bin_, iface, path = prof["bin"], prof["iface"], prof["conf"]
            code, _, _ = self._script(container, f"{bin_} syncconf {iface} <({bin_}-quick strip {path})\n")
            if code != 0:
                self.ssh.run(f"{self.docker} restart {container}", timeout=self.install_timeout)
        self._table_remove(container, client_id)
        self._drop_wg_secret(container, client_id)

    def _delete_openvpn_client(self, container: str, client_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", client_id):
            raise SSHError("Некорректный идентификатор клиента")
        code, out, err = self._script(
            container,
            f"cd {OPENVPN_DIR} && export EASYRSA_BATCH=1 && "
            f"easyrsa revoke {client_id} && easyrsa gen-crl && "
            f"chmod 666 pki/crl.pem && cp pki/crl.pem .\n",
            timeout=self.install_timeout,
        )
        if code != 0:
            raise SSHError(err.strip() or out.strip() or "Не удалось отозвать сертификат")
        self._table_remove(container, client_id)

    def _delete_xray_client(self, container: str, client_id: str) -> None:
        config = self._xray_config(container)
        inbound = self._xray_inbound(config)
        clients = inbound.get("settings", {}).get("clients", [])
        new = [c for c in clients if c.get("id") != client_id]
        if len(new) != len(clients):
            inbound["settings"]["clients"] = new
            backup = self._read(container, XRAY_SERVER_CONFIG)
            self._apply_xray_config(container, config, backup)
        self._table_remove(container, client_id)

    # ------------------------------------------------------------------
    # Создание контейнеров (как InstallController в amnezia-client)
    # ------------------------------------------------------------------

    def create_container(self, protocol: str, port: int, transport: str = "udp") -> dict:
        specs = {
            "awg2": ("amnezia-awg2", "awg"),
            "wireguard": ("amnezia-wireguard", "wireguard"),
            "openvpn": ("amnezia-openvpn", "openvpn"),
            "xray": ("amnezia-xray", "xray"),
            "ipsec": ("amnezia-ipsec", "ipsec"),
        }
        if protocol not in specs:
            return {"ok": False, "error": f"Протокол '{protocol}' не поддерживается"}
        if protocol != "ipsec" and not (1 <= port <= 65535):
            return {"ok": False, "error": "Некорректный порт"}
        transport = (transport or "udp").lower()
        if protocol == "openvpn" and transport not in ("udp", "tcp"):
            return {"ok": False, "error": "Для OpenVPN выберите udp или tcp"}
        name, script_dir = specs[protocol]
        if self.container_exists(name):
            return {"ok": False, "error": f"Контейнер {name} уже существует"}

        variables = self._install_variables(protocol, name, port, transport)
        try:
            self._install_from_scripts(name, script_dir, variables, port)
            if protocol == "xray":
                self._write_initial_xray_config(name, port)
            self._write(name, self._table_path(name), "[]")
        except SSHError as exc:
            return {"ok": False, "error": str(exc)}

        time.sleep(2)
        return {"ok": True, "container": name, "protocol": protocol, "port": port}

    def _install_variables(self, protocol: str, name: str, port: int, transport: str) -> dict:
        subnet_ip, subnet_cidr = ("10.8.0.0", "24") if protocol == "openvpn" else ("10.8.1.0", "24")
        variables = {
            "$CONTAINER_NAME": name,
            "$DOCKERFILE_FOLDER": f"/opt/amnezia/{name}",
            "$SERVER_IP_ADDRESS": self.ssh.host,
            "$PRIMARY_DNS": self.primary_dns,
            "$SECONDARY_DNS": self.secondary_dns,
            "$PRIMARY_SERVER_DNS": self.primary_dns,
            "$SECONDARY_SERVER_DNS": self.secondary_dns,
            "$WIREGUARD_SUBNET_IP": subnet_ip,
            "$WIREGUARD_SUBNET_CIDR": subnet_cidr,
            "$WIREGUARD_SERVER_PORT": str(port),
            "$AWG_SUBNET_IP": subnet_ip,
            "$AWG_SERVER_PORT": str(port),
            "$OPENVPN_SUBNET_IP": "10.8.0.0",
            "$OPENVPN_SUBNET_CIDR": "24",
            "$OPENVPN_SUBNET_MASK": "255.255.255.0",
            "$OPENVPN_PORT": str(port),
            "$OPENVPN_TRANSPORT_PROTO": transport if protocol == "openvpn" else "udp",
            "$OPENVPN_NCP_DISABLE": "",
            "$OPENVPN_CIPHER": "AES-256-GCM",
            "$OPENVPN_HASH": "SHA512",
            "$OPENVPN_TLS_AUTH": "tls-auth /opt/amnezia/openvpn/ta.key 0",
            "$OPENVPN_ADDITIONAL_CLIENT_CONFIG": "",
            "$OPENVPN_ADDITIONAL_SERVER_CONFIG": "",
            "$XRAY_SERVER_PORT": str(port),
            "$XRAY_SITE_NAME": "www.googletagmanager.com",
            "$IPSEC_VPN_L2TP_NET": "192.168.42.0/24",
            "$IPSEC_VPN_L2TP_POOL": "192.168.42.10-192.168.42.250",
            "$IPSEC_VPN_L2TP_LOCAL": "192.168.42.1",
            "$IPSEC_VPN_XAUTH_NET": "192.168.43.0/24",
            "$IPSEC_VPN_XAUTH_POOL": "192.168.43.10-192.168.43.250",
            "$IPSEC_VPN_SHA2_TRUNCBUG": "yes",
            "$IPSEC_VPN_VPN_ANDROID_MTU_FIX": "yes",
            "$IPSEC_VPN_DISABLE_IKEV2": "no",
            "$IPSEC_VPN_DISABLE_L2TP": "no",
            "$IPSEC_VPN_DISABLE_XAUTH": "no",
            "$IPSEC_VPN_C2C_TRAFFIC": "no",
        }
        if protocol == "awg2":
            variables.update({
                "$JUNK_PACKET_COUNT": str(secrets.choice(range(4, 7))),
                "$JUNK_PACKET_MIN_SIZE": "10",
                "$JUNK_PACKET_MAX_SIZE": "50",
                "$INIT_PACKET_JUNK_SIZE": "12",
                "$RESPONSE_PACKET_JUNK_SIZE": "12",
                "$COOKIE_REPLY_PACKET_JUNK_SIZE": "12",
                "$TRANSPORT_PACKET_JUNK_SIZE": "12",
                "$INIT_PACKET_MAGIC_HEADER": "1",
                "$RESPONSE_PACKET_MAGIC_HEADER": "2",
                "$UNDERLOAD_PACKET_MAGIC_HEADER": "3",
                "$TRANSPORT_PACKET_MAGIC_HEADER": "4",
                "$HEADER_PROTECTION_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
                "$CONTENT_PADDING_ADDITION": "",
                "$REKEY_AFTER_TIME": "100-120",
                "$REKEY_TIMEOUT": "3-7",
                "$REJECT_AFTER_TIME": "150-180",
                "$KEEPALIVE_TIMEOUT": "5-15",
                "$MAX_HANDSHAKE_ATTEMPTS": "15-20",
                "$RANDOM_TRAILERS": "on",
                "$DISABLE_COOKIES": "on",
                "$SPECIAL_JUNK_1": AWG_DEFAULT_SPECIAL_JUNK_1,
                "$SPECIAL_JUNK_2": "", "$SPECIAL_JUNK_3": "",
                "$SPECIAL_JUNK_4": "", "$SPECIAL_JUNK_5": "",
            })
        return variables

    def _install_from_scripts(self, name: str, script_dir: str, variables: dict, port: int) -> None:
        folder = variables["$DOCKERFILE_FOLDER"]
        sudo = "" if self.docker == "docker" else "sudo "
        dockerfile = self._script_text(script_dir, "Dockerfile")
        run_script = self._subst(self._script_text(script_dir, "run_container.sh"), variables)
        configure = self._subst(self._script_text(script_dir, "configure_container.sh"), variables)
        start = self._subst(self._script_text(script_dir, "start.sh"), variables)

        self._host(f"{sudo}mkdir -p {folder} && {sudo}sysctl -w net.ipv4.ip_forward=1 >/dev/null")
        self._host(
            f"{self.docker} network ls | grep -q amnezia-dns-net || "
            f"{self.docker} network create --driver bridge --subnet=172.29.172.0/24 "
            f"--opt com.docker.network.bridge.name=amn0 amnezia-dns-net"
        )
        self._host(f"{sudo}tee {folder}/Dockerfile >/dev/null", input_data=dockerfile)
        self._host(
            f"{self.docker} build --no-cache --pull -t {name} {folder} 2>&1",
            timeout=self.install_timeout,
        )
        out = self._host("bash -s 2>&1", timeout=self.install_timeout, input_data=run_script)
        if "already in use" in out or "address already in use" in out:
            raise SSHError(f"Порт {port} уже занят")
        code, out, err = self._script(name, configure, timeout=self.install_timeout)
        if code != 0:
            raise SSHError(err.strip() or out.strip() or "configure_container.sh завершился с ошибкой")
        if start.strip():
            self._write(name, "/opt/amnezia/start.sh", start)
            self._host(
                f"{self.docker} exec -d {name} sh -c "
                f"\"chmod a+x /opt/amnezia/start.sh && /opt/amnezia/start.sh\""
            )

    def _write_initial_xray_config(self, name: str, port: int) -> None:
        private_key = self._read(name, f"{XRAY_DIR}/xray_private.key").strip()
        public_key = self._read(name, f"{XRAY_DIR}/xray_public.key").strip()
        short_id = self._read(name, f"{XRAY_DIR}/xray_short_id.key").strip()
        client_id = self._read(name, f"{XRAY_DIR}/xray_uuid.key").strip()
        if not (private_key and public_key and short_id and client_id):
            raise SSHError("XRay не сгенерировал ключи Reality")
        config = default_xray_server(port, private_key, short_id, client_id)
        self._write(name, XRAY_SERVER_CONFIG, json.dumps(config, indent=2) + "\n")

    def _script_text(self, script_dir: str, filename: str) -> str:
        path = os.path.join(SCRIPTS_DIR, script_dir, filename)
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def _subst(self, text: str, variables: dict) -> str:
        for key in sorted(variables, key=len, reverse=True):
            text = text.replace(key, variables[key])
        return text.replace("sudo docker", self.docker)

    def _host(self, cmd: str, timeout: int | None = None, input_data: str | None = None) -> str:
        code, out, err = self.ssh.run(cmd, timeout=timeout or self.timeout, input_data=input_data)
        if code != 0:
            raise SSHError((err.strip() or out.strip() or f"Ошибка: {cmd}")[-2000:])
        return out

    # ------------------------------------------------------------------
    # Редактор настроек соединения
    # ------------------------------------------------------------------

    def connection_settings(self, container: str) -> dict:
        if not self._validate_container(container):
            return {"ok": False, "error": "Контейнер не разрешён"}
        if not self.container_running(container):
            return {"ok": False, "error": f"Контейнер {container} не запущен"}
        kind = self._settings_kind(container)
        if kind is None:
            return {"ok": False, "error": "Для этого контейнера нет редактора настроек"}
        try:
            values = self._read_settings_values(container, kind)
        except SSHError as exc:
            return {"ok": False, "error": str(exc)}
        form = settings_form(kind, values)
        form.update({"ok": True, "protocol": kind, "container": container, "values": values})
        return form

    def update_connection_settings(self, container: str, fields: dict) -> dict:
        if not self._validate_container(container):
            return {"ok": False, "error": "Контейнер не разрешён"}
        if not self.container_running(container):
            return {"ok": False, "error": f"Контейнер {container} не запущен"}
        kind = self._settings_kind(container)
        if kind is None:
            return {"ok": False, "error": "Для этого контейнера нет редактора настроек"}
        try:
            if kind in ("awg", "wireguard"):
                self._update_wg_settings(container, fields, awg=kind == "awg")
            elif kind == "openvpn":
                self._update_openvpn_settings(container, fields)
            elif kind == "xray":
                self._update_xray_settings(container, fields)
            elif kind == "ipsec":
                self._update_ipsec_settings(container, fields)
        except SSHError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def remove_container(self, container: str) -> dict:
        if not self._validate_container(container):
            return {"ok": False, "error": "Контейнер не разрешён"}
        if not self.container_exists(container):
            return {"ok": False, "error": "Контейнер не найден"}
        try:
            self._host(f"{self.docker} stop {container} && {self.docker} rm -f {container}")
            self._host(f"{self.docker} rmi {container} >/dev/null 2>&1 || true")
        except SSHError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}

    def _settings_kind(self, container: str) -> str | None:
        if container in WG_PROFILES:
            return "awg" if WG_PROFILES[container]["awg"] else "wireguard"
        return {
            "amnezia-openvpn": "openvpn",
            "amnezia-xray": "xray",
            "amnezia-ipsec": "ipsec",
        }.get(container)

    def _read_settings_values(self, container: str, kind: str) -> dict:
        if kind in ("awg", "wireguard"):
            prof = WG_PROFILES[container]
            conf = self._read(container, prof["conf"])
            if not conf.strip():
                raise SSHError(f"Не найден {prof['conf']}")
            interface, _peers = _parse_wg_conf(conf)
            opts = self._read_json(container, f"{prof['dir']}/panel_client_opts.json")
            return wg_form_values(interface, kind == "awg", str(opts.get("mtu") or DEFAULT_MTU))
        if kind == "openvpn":
            conf = self._read(container, f"{OPENVPN_DIR}/server.conf")
            if not conf.strip():
                raise SSHError("Не найден /opt/amnezia/openvpn/server.conf")
            return openvpn_form_values(conf, self._read_json(container, f"{OPENVPN_DIR}/panel_client_opts.json"))
        if kind == "xray":
            return xray_form_values(self._xray_config(container))
        ipsec_conf = self._read(container, "/etc/ipsec.conf")
        if not ipsec_conf.strip():
            ipsec_conf = self._read(container, "/etc/ipsec.d/ikev2.conf")
        ppp = self._read(container, "/etc/ppp/options.xl2tpd")
        if not ipsec_conf.strip() and not ppp.strip():
            raise SSHError("Не найден конфиг IPsec")
        return ipsec_form_values(ipsec_conf, ppp)

    def _update_wg_settings(self, container: str, fields: dict, awg: bool) -> None:
        prof = WG_PROFILES[container]
        current = self._read(container, prof["conf"])
        interface, _peers = _parse_wg_conf(current)
        old_port = interface.get("ListenPort", "")
        rendered, errors = apply_wg_settings(current, fields, awg)
        if errors:
            raise SSHError("; ".join(errors))
        rendered_iface = _parse_wg_conf(rendered)[0]
        new_port = rendered_iface.get("ListenPort", "")
        address, prefix = rendered_iface.get("Address", "10.8.1.0/24").split("/", 1)
        opts_path = f"{prof['dir']}/panel_client_opts.json"
        opts = self._read_json(container, opts_path)
        opts["mtu"] = str(fields.get("mtu") or DEFAULT_MTU)
        if new_port != old_port:
            self._recreate_published(
                container,
                [(new_port, "udp")],
                self._wg_run_args(),
            )
        self._write(container, prof["conf"], rendered)
        self._write(container, opts_path, json.dumps(opts, indent=2) + "\n")
        self._rewrite_start(container, {
            "$AWG_SUBNET_IP": address,
            "$WIREGUARD_SUBNET_IP": address,
            "$WIREGUARD_SUBNET_CIDR": prefix,
            "$AWG_SERVER_PORT": new_port,
            "$WIREGUARD_SERVER_PORT": new_port,
        })
        self._host(f"{self.docker} restart {container}", timeout=self.install_timeout)

    def _update_openvpn_settings(self, container: str, fields: dict) -> None:
        current = self._read(container, f"{OPENVPN_DIR}/server.conf")
        old = openvpn_form_values(current)
        rendered, client_opts, errors = render_openvpn_conf(fields)
        if errors:
            raise SSHError("; ".join(errors))
        new = openvpn_form_values(rendered, client_opts)
        if old.get("port") != new["port"] or old.get("proto") != new["proto"]:
            self._recreate_published(container, [(new["port"], new["proto"])], self._openvpn_run_args())
        self._write(container, f"{OPENVPN_DIR}/server.conf", rendered)
        self._write(
            container,
            f"{OPENVPN_DIR}/panel_client_opts.json",
            json.dumps(client_opts, indent=2) + "\n",
        )
        address, prefix = new["subnet"].split("/")
        self._rewrite_start(container, {
            "$OPENVPN_SUBNET_IP": address,
            "$OPENVPN_SUBNET_CIDR": prefix,
            "$OPENVPN_PORT": new["port"],
            "$SERVER_IP_ADDRESS": self.ssh.host,
        })
        self._host(f"{self.docker} restart {container}", timeout=self.install_timeout)

    def _update_xray_settings(self, container: str, fields: dict) -> None:
        config = self._xray_config(container)
        old_port = str(xray_form_values(config).get("port") or "")
        security = str(fields.get("security") or "")
        if security == "tls":
            self._ensure_xray_tls(container)
        private_key = self._read(container, f"{XRAY_DIR}/xray_private.key").strip()
        short_id = self._read(container, f"{XRAY_DIR}/xray_short_id.key").strip()
        payload = dict(fields)
        payload["_private_key"] = private_key
        payload["_short_id"] = short_id
        updated, errors = apply_xray_settings(config, payload)
        if errors:
            raise SSHError("; ".join(errors))
        new_port = str(xray_form_values(updated).get("port") or "")
        if new_port != old_port:
            self._recreate_published(
                container,
                [(new_port, "tcp"), (new_port, "udp")],
                "--privileged --log-driver none --restart always --cap-add=NET_ADMIN "
                f"-v {container}-data:/opt/amnezia/xray",
            )
        self._rewrite_start(container, {"$XRAY_SERVER_PORT": new_port})
        backup = self._read(container, XRAY_SERVER_CONFIG)
        self._apply_xray_config(container, updated, backup)

    def _update_ipsec_settings(self, container: str, fields: dict) -> None:
        primary = str(fields.get("primary_dns", "")).strip()
        secondary = str(fields.get("secondary_dns", "")).strip()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", primary):
            raise SSHError("Некорректный основной DNS")
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", secondary):
            raise SSHError("Некорректный второй DNS")
        for path in ("/etc/ipsec.conf", "/etc/ipsec.d/ikev2.conf", "/etc/ppp/options.xl2tpd"):
            current = self._read(container, path)
            if not current.strip():
                continue
            self._write(container, path, apply_ipsec_dns(current, primary, secondary))
        self._host(f"{self.docker} restart {container}", timeout=self.install_timeout)

    def _ensure_xray_tls(self, container: str) -> None:
        cert = self._read(container, f"{XRAY_DIR}/tls_cert.pem")
        key = self._read(container, f"{XRAY_DIR}/tls_key.pem")
        if "BEGIN" in cert and "BEGIN" in key:
            return
        script = (
            f"openssl req -x509 -newkey rsa:2048 -nodes -days 3650 "
            f"-keyout {XRAY_DIR}/tls_key.pem -out {XRAY_DIR}/tls_cert.pem "
            f"-subj /CN=www.googletagmanager.com"
        )
        code, out, err = self._exec(container, script, timeout=self.install_timeout)
        if code != 0:
            raise SSHError(err.strip() or out.strip() or "Не удалось выпустить TLS-сертификат XRay")

    def _wg_run_args(self) -> str:
        return (
            "--log-driver none --restart always --privileged "
            "--cap-add=NET_ADMIN --cap-add=SYS_MODULE "
            "-v /lib/modules:/lib/modules --sysctl=net.ipv4.conf.all.src_valid_mark=1"
        )

    def _openvpn_run_args(self) -> str:
        return "--privileged --log-driver none --restart always --cap-add=NET_ADMIN"

    def _recreate_published(self, container: str, publishes: list[tuple[str, str]], run_args: str) -> None:
        """Пересоздаёт контейнер с новыми проброшенными портами, сохраняя /opt/amnezia."""
        code, image, err = self.ssh.run(
            f"{self.docker} inspect -f '{{{{.Config.Image}}}}' {container}",
            timeout=self.timeout,
        )
        image = image.strip()
        if code != 0 or not image:
            raise SSHError(err.strip() or "Не удалось узнать образ контейнера")
        code, archive, err = self.ssh.run(
            f"{self.docker} exec {container} tar -C / -czf - opt/amnezia | base64 -w 0",
            timeout=self.install_timeout,
        )
        if code != 0 or not archive.strip():
            raise SSHError(err.strip() or "Не удалось сохранить файлы контейнера перед сменой порта")
        parked = f"{container}-replacing"
        self._host(f"{self.docker} rename {container} {parked}")
        publish = " ".join(f"-p {port}:{port}/{proto}" for port, proto in publishes)
        try:
            self._host(
                f"{self.docker} run -d {run_args} {publish} --name {container} {image}",
                timeout=self.install_timeout,
            )
            self._host(
                f"base64 -d | {self.docker} exec -i {container} tar -C / -xzf -",
                timeout=self.install_timeout,
                input_data=archive.strip(),
            )
            self.ssh.run(
                f"{self.docker} network connect amnezia-dns-net {container} >/dev/null 2>&1 || true",
                timeout=self.timeout,
            )
        except SSHError:
            self.ssh.run(f"{self.docker} rm -f {container} >/dev/null 2>&1 || true", timeout=self.timeout)
            self.ssh.run(f"{self.docker} rename {parked} {container} >/dev/null 2>&1 || true", timeout=self.timeout)
            raise
        self.ssh.run(f"{self.docker} rm -f {parked} >/dev/null 2>&1 || true", timeout=self.timeout)

    def _rewrite_start(self, container: str, variables: dict) -> None:
        script_name = {
            "amnezia-awg2": "awg/start.sh",
            "amnezia-awg": "awg_legacy/start.sh",
            "amnezia-wireguard": "wireguard/start.sh",
            "amnezia-openvpn": "openvpn/start.sh",
            "amnezia-xray": "xray/start.sh",
        }.get(container)
        if not script_name:
            return
        directory, filename = script_name.split("/", 1)
        text = self._subst(self._script_text(directory, filename), variables)
        if text.strip():
            self._write(container, "/opt/amnezia/start.sh", text)
