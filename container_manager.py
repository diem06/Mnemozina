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
from urllib.parse import quote

from ssh_manager import SSHSession, SSHError

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


def _parse_wg_conf(conf: str) -> tuple[dict, list[dict]]:
    """
    Разбирает wg/awg-конфиг сервера.
    Возвращает (interface: dict, peers: [dict]).
    Закомментированные "# I1 = ..." в [Interface] тоже читаются (так их хранит
    amnezia-client: I1–I5 нужны только клиенту).
    """
    interface: dict[str, str] = {}
    peers: list[dict] = []
    section = None
    current: dict | None = None
    for raw in conf.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                current = {}
                peers.append(current)
            continue
        target = interface if section == "interface" else current
        if target is None:
            continue
        commented = False
        if line.startswith("#"):
            line = line.lstrip("#").strip()
            commented = True
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if commented:
            # Нужны только закомментированные I1..I5
            if section == "interface" and re.fullmatch(r"I[1-5]", key) and key not in interface:
                interface[key] = value
            continue
        target[key] = value
    return interface, peers


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

    def _list_xray_clients(self, container: str) -> list[dict]:
        config = self._xray_config(container)
        inbounds = config.get("inbounds") or [{}]
        clients = inbounds[0].get("settings", {}).get("clients", [])
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

        # 4. Собираем клиентский конфиг (server_scripts/awg/template.conf)
        port = interface.get("ListenPort") or "51820"
        dns1, dns2 = self._dns()
        lines = [
            "[Interface]",
            f"Address = {client_ip}/32",
            f"DNS = {dns1}, {dns2}",
            f"PrivateKey = {priv}",
        ]
        is_awg3 = False
        if prof["awg"]:
            for key in AWG_CLIENT_KEYS:
                value = interface.get(key, "").strip()
                if value and not value.startswith("$"):
                    lines.append(f"{key} = {value}")
            is_awg3 = any(interface.get(k) for k in AWG3_MARKERS) or \
                interface.get("RandomTrailers") == "on" or interface.get("DisableCookies") == "on"
        lines.append(f"MTU = {DEFAULT_MTU}")
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {server_pub}",
        ]
        if psk:
            lines.append(f"PresharedKey = {psk}")
        lines += [
            "AllowedIPs = 0.0.0.0/0, ::/0",
            f"Endpoint = {self._server_host()}:{port}",
            f"PersistentKeepalive = {'25-35' if is_awg3 else '25'}",
            "",
        ]
        return {
            "ok": True, "client": client_name, "config": "\n".join(lines),
            "filename": f"{self._safe_filename(client_name)}.conf", "error": None,
        }

    @staticmethod
    def _safe_filename(name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "client"

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

        ca = self._pem_only(self._read(container, f"{OPENVPN_DIR}/pki/ca.crt"))
        cert = self._pem_only(self._read(container, f"{OPENVPN_DIR}/pki/issued/{client_id}.crt"))
        key = self._pem_only(self._read(container, f"{OPENVPN_DIR}/pki/private/{client_id}.key"))
        ta = "\n".join(
            l for l in self._read(container, f"{OPENVPN_DIR}/ta.key").splitlines()
            if not l.strip().startswith("#")
        ).strip()
        if not (ca and cert and key):
            raise SSHError("Не удалось прочитать сертификаты клиента")

        server_conf = self._read(container, f"{OPENVPN_DIR}/server.conf")
        opts: dict[str, str] = {}
        for line in server_conf.splitlines():
            parts = line.strip().split(None, 1)
            if parts:
                opts.setdefault(parts[0], parts[1] if len(parts) > 1 else "")
        port_code, port_out, _ = self.ssh.run(
            f"{self.docker} port {container} 2>/dev/null | head -n1", timeout=self.timeout
        )
        m = re.search(r":(\d+)\s*$", port_out.strip())
        port = m.group(1) if m else opts.get("port", "1194")
        proto = opts.get("proto", "udp")
        dns1, dns2 = self._dns()

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
            f"dhcp-option DNS {dns1}", f"dhcp-option DNS {dns2}", "block-outside-dns", "",
            f"remote {self._server_host()} {port}", "",
            "<ca>", ca, "</ca>", "<cert>", cert, "</cert>", "<key>", key, "</key>",
        ]
        if ta and "tls-auth" in opts:
            cfg += ["<tls-auth>", ta, "</tls-auth>"]
        self._table_add(container, client_id, client_name)
        return {
            "ok": True, "client": client_name, "config": "\n".join(cfg) + "\n",
            "filename": f"{self._safe_filename(client_name)}.ovpn", "error": None,
        }

    def _add_xray_client(self, container: str, client_name: str) -> dict:
        config = self._xray_config(container)
        inbounds = config.get("inbounds") or []
        if not inbounds:
            raise SSHError("В конфиге XRay нет inbounds")
        inbound = inbounds[0]
        stream = inbound.get("streamSettings", {})
        security = stream.get("security", "none")
        network = stream.get("network", "tcp")
        clients = inbound.setdefault("settings", {}).setdefault("clients", [])
        flow = next((c.get("flow") for c in clients if c.get("flow")), None)
        if flow is None and security == "reality" and network in ("tcp", "raw"):
            flow = "xtls-rprx-vision"

        client_id = str(uuid_module.uuid4())
        entry = {"id": client_id}
        if flow:
            entry["flow"] = flow
        clients.append(entry)

        self._write(container, XRAY_SERVER_CONFIG, json.dumps(config, indent=4))
        self.ssh.run(f"{self.docker} restart {container}", timeout=self.install_timeout)
        self._table_add(container, client_id, client_name)

        reality = stream.get("realitySettings", {})
        pbk = self._read(container, f"{XRAY_DIR}/xray_public.key").strip()
        sid = self._read(container, f"{XRAY_DIR}/xray_short_id.key").strip() or \
            (reality.get("shortIds") or [""])[0]
        sni = (reality.get("serverNames") or [""])[0]
        port = inbound.get("port", 443)

        params = [f"type={network}", f"security={security}", "encryption=none"]
        if flow:
            params.append(f"flow={flow}")
        if security == "reality":
            params += [f"sni={sni}", "fp=chrome", f"pbk={pbk}", f"sid={sid}"]
        link = f"vless://{client_id}@{self._server_host()}:{port}?{'&'.join(params)}#{quote(client_name)}"
        return {
            "ok": True, "client": client_name, "config": link,
            "filename": f"{self._safe_filename(client_name)}.txt", "error": None,
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
        changed = False
        for inbound in config.get("inbounds", []):
            clients = inbound.get("settings", {}).get("clients", [])
            new = [c for c in clients if c.get("id") != client_id]
            if len(new) != len(clients):
                inbound["settings"]["clients"] = new
                changed = True
        if changed:
            self._write(container, XRAY_SERVER_CONFIG, json.dumps(config, indent=4))
            self.ssh.run(f"{self.docker} restart {container}", timeout=self.install_timeout)
        self._table_remove(container, client_id)

    # ------------------------------------------------------------------
    # Создание контейнеров (как InstallController в amnezia-client)
    # ------------------------------------------------------------------

    def create_container(self, protocol: str, port: int) -> dict:
        if protocol not in ("awg2", "wireguard"):
            return {"ok": False, "error": f"Протокол '{protocol}' не поддерживается"}
        if not (1 <= port <= 65535):
            return {"ok": False, "error": "Некорректный порт"}
        name = {"awg2": "amnezia-awg2", "wireguard": "amnezia-wireguard"}[protocol]
        if self.container_exists(name):
            return {"ok": False, "error": f"Контейнер {name} уже существует"}

        scripts_dir = os.path.join(SCRIPTS_DIR, "awg" if protocol == "awg2" else "wireguard")
        read = lambda f: open(os.path.join(scripts_dir, f), encoding="utf-8").read()  # noqa: E731

        subnet_ip, subnet_cidr = "10.8.1.0", "24"
        variables = {
            "$CONTAINER_NAME": name,
            "$DOCKERFILE_FOLDER": f"/opt/amnezia/{name}",
            "$WIREGUARD_SUBNET_IP": subnet_ip,
            "$WIREGUARD_SUBNET_CIDR": subnet_cidr,
            "$WIREGUARD_SERVER_PORT": str(port),
            "$AWG_SUBNET_IP": subnet_ip,
            "$AWG_SERVER_PORT": str(port),
        }
        if protocol == "awg2":
            # Значения как в AwgInstaller::generateAwgParameters (версия 3.1)
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

        def subst(text: str) -> str:
            # длинные имена первыми, чтобы $AWG_SUBNET_IP не съел $AWG_SUBNET_IP_X и т.п.
            for key in sorted(variables, key=len, reverse=True):
                text = text.replace(key, variables[key])
            return text.replace("sudo docker", self.docker)

        folder = variables["$DOCKERFILE_FOLDER"]
        sudo = "" if self.docker == "docker" else "sudo "

        def host(cmd: str, timeout: int | None = None, input_data: str | None = None):
            code, out, err = self.ssh.run(cmd, timeout=timeout or self.timeout, input_data=input_data)
            if code != 0:
                raise SSHError((err.strip() or out.strip() or f"Ошибка: {cmd}")[-2000:])
            return out

        try:
            # prepare_host.sh
            host(f"{sudo}mkdir -p {folder} && {sudo}sysctl -w net.ipv4.ip_forward=1 >/dev/null")
            host(
                f"{self.docker} network ls | grep -q amnezia-dns-net || "
                f"{self.docker} network create --driver bridge --subnet=172.29.172.0/24 "
                f"--opt com.docker.network.bridge.name=amn0 amnezia-dns-net"
            )
            # build_container.sh
            host(f"{sudo}tee {folder}/Dockerfile >/dev/null", input_data=read("Dockerfile"))
            host(f"{self.docker} build --no-cache --pull -t {name} {folder} 2>&1",
                 timeout=self.install_timeout)
            # run_container.sh
            run_script = subst(read("run_container.sh"))
            out = host(f"bash -s 2>&1", timeout=self.install_timeout, input_data=run_script)
            if "already in use" in out or "address already in use" in out:
                raise SSHError(f"Порт {port} уже занят")
            # configure_container.sh — внутри контейнера
            code, out, err = self._script(name, subst(read("configure_container.sh")))
            if code != 0:
                raise SSHError(err.strip() or out.strip() or "configure_container.sh завершился с ошибкой")
            # start.sh
            self._write(name, "/opt/amnezia/start.sh", subst(read("start.sh")))
            host(f"{self.docker} exec -d {name} sh -c "
                 f"\"chmod a+x /opt/amnezia/start.sh && /opt/amnezia/start.sh\"")
            self._write(name, self._table_path(name), "[]")
        except SSHError as exc:
            return {"ok": False, "error": str(exc)}

        time.sleep(2)
        return {"ok": True, "container": name, "protocol": protocol, "port": port}
