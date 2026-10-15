"""Разбор и запись настроек соединения контейнеров Amnezia VPN.

Поля совпадают с редакторами amnezia-client: серверные страницы
AmneziaWG, WireGuard, OpenVPN и XRay. Функции не ходят на сервер —
их вызывает ContainerManager.
"""
from __future__ import annotations

import ipaddress
import json
import re

AWG_INTERFACE_KEYS = [
    "PrivateKey", "Address", "ListenPort",
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
    "H1", "H2", "H3", "H4",
    "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts",
    "RandomTrailers", "DisableCookies",
]
AWG_COMMENT_KEYS = ["I1", "I2", "I3", "I4", "I5"]
WG_INTERFACE_KEYS = ["PrivateKey", "Address", "ListenPort"]

OPENVPN_CIPHERS = [
    "AES-256-GCM", "AES-192-GCM", "AES-128-GCM",
    "AES-256-CBC", "AES-192-CBC", "AES-128-CBC",
    "ChaCha20-Poly1305", "ARIA-256-CBC", "CAMELLIA-256-CBC", "none",
]
OPENVPN_HASHES = [
    "SHA512", "SHA384", "SHA256", "SHA3-512", "SHA3-384", "SHA3-256",
    "whirlpool", "BLAKE2b512", "BLAKE2s256", "SHA1",
]

XRAY_TRANSPORTS = [
    ("raw", "RAW (TCP)"),
    ("xhttp", "XHTTP"),
    ("mkcp", "mKCP"),
]
XRAY_SECURITY = [
    ("none", "Нет"),
    ("tls", "TLS"),
    ("reality", "Reality"),
]
XRAY_FLOWS = [
    ("", "Пусто"),
    ("xtls-rprx-vision", "xtls-rprx-vision"),
    ("xtls-rprx-vision-udp443", "xtls-rprx-vision-udp443"),
]
XRAY_FINGERPRINTS = [
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
]
XRAY_ALPN = ["h2", "http/1.1", "h2,http/1.1"]
XRAY_XHTTP_MODES = ["Stream-one", "Stream-up"]
XRAY_DEFAULT_SITE = "www.googletagmanager.com"

_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")


def parse_wg_conf(conf: str) -> tuple[dict, list[dict]]:
    """Разбирает wg/awg-конфиг. Закомментированные I1–I5 тоже читаются."""
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
            if section == "interface" and re.fullmatch(r"I[1-5]", key) and key not in interface:
                interface[key] = value
            continue
        target[key] = value
    return interface, peers


def render_wg_conf(interface: dict, peers: list[dict], awg: bool) -> str:
    lines = ["[Interface]"]
    order = AWG_INTERFACE_KEYS if awg else WG_INTERFACE_KEYS
    seen = set()
    for key in order:
        seen.add(key)
        value = str(interface.get(key, "")).strip()
        if not value:
            continue
        lines.append(f"{key} = {value}")
    if awg:
        for key in AWG_COMMENT_KEYS:
            seen.add(key)
            value = str(interface.get(key, "")).strip()
            if value:
                lines.append(f"# {key} = {value}")
    for key, value in interface.items():
        if key in seen or not str(value).strip():
            continue
        lines.append(f"{key} = {value}")
    for peer in peers:
        lines += ["", "[Peer]"]
        for key, value in peer.items():
            if str(value).strip():
                lines.append(f"{key} = {value}")
    return "\n".join(lines) + "\n"


def _subnet_text(address: str) -> str:
    address = (address or "").strip()
    if not address:
        return ""
    if "/" in address:
        return address
    return f"{address}/24"


def wg_form_values(interface: dict, awg: bool, mtu: str) -> dict:
    address = interface.get("Address", "")
    values = {
        "subnet": address if "/" in address else (_subnet_text(address) if address else ""),
        "port": interface.get("ListenPort", ""),
        "mtu": mtu or "1376",
    }
    if awg:
        for key in AWG_INTERFACE_KEYS + AWG_COMMENT_KEYS:
            if key in ("PrivateKey", "Address", "ListenPort"):
                continue
            values[key] = interface.get(key, "")
    return values


def _require_port(value: str, errors: list[str]) -> str:
    try:
        port = int(str(value).strip())
    except ValueError:
        errors.append("Порт должен быть числом от 1 до 65535")
        return ""
    if not 1 <= port <= 65535:
        errors.append("Порт должен быть числом от 1 до 65535")
        return ""
    return str(port)


def _require_subnet(value: str, errors: list[str]) -> str:
    text = str(value or "").strip()
    if "/" not in text:
        text = f"{text}/24" if text else ""
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        errors.append("Подсеть VPN должна быть адресом IPv4 с маской, например 10.8.1.0/24")
        return ""
    if not isinstance(network, ipaddress.IPv4Network):
        errors.append("Подсеть VPN должна быть IPv4")
        return ""
    return f"{network.network_address}/{network.prefixlen}"


def apply_wg_settings(conf: str, fields: dict, awg: bool) -> tuple[str, list[str]]:
    errors: list[str] = []
    interface, peers = parse_wg_conf(conf)
    subnet = _require_subnet(fields.get("subnet", ""), errors)
    port = _require_port(fields.get("port", ""), errors)
    mtu = str(fields.get("mtu", "")).strip() or "1376"
    if not mtu.isdigit() or not 576 <= int(mtu) <= 1500:
        errors.append("MTU клиента должен быть числом от 576 до 1500")
    if awg:
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
            raw = str(fields.get(key, "")).strip()
            if raw and not re.fullmatch(r"\d{1,6}", raw):
                errors.append(f"{key} должно быть целым числом")
        headers = [str(fields.get(key, "")).strip() for key in ("H1", "H2", "H3", "H4")]
        filled = [item for item in headers if item]
        if len(filled) != len(set(filled)):
            errors.append("H1–H4 должны отличаться друг от друга")
        for key in ("RandomTrailers", "DisableCookies"):
            raw = str(fields.get(key, "")).strip().lower()
            if raw and raw not in ("on", "off"):
                errors.append(f"{key} может быть только on или off")
    if errors:
        return conf, errors
    interface["Address"] = subnet
    interface["ListenPort"] = port
    if awg:
        for key in AWG_INTERFACE_KEYS + AWG_COMMENT_KEYS:
            if key in ("PrivateKey", "Address", "ListenPort"):
                continue
            interface[key] = str(fields.get(key, "")).strip()
    return render_wg_conf(interface, peers, awg), []


def _openvpn_lines(conf: str) -> list[tuple[str, str]]:
    rows = []
    for raw in conf.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        rows.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return rows


_OPENVPN_MANAGED = {
    "port", "proto", "dev", "ca", "cert", "key", "dh", "server",
    "ifconfig-pool-persist", "duplicate-cn", "keepalive", "ncp-disable",
    "cipher", "data-ciphers", "auth", "user", "group", "persist-key",
    "persist-tun", "crl-verify", "status", "verb", "tls-server",
    "tls-version-min", "tls-auth",
}


def openvpn_form_values(conf: str, client_opts: dict | None = None) -> dict:
    opts = dict(client_opts or {})
    rows = _openvpn_lines(conf)
    first: dict[str, str] = {}
    extra: list[str] = []
    for key, value in rows:
        if key not in _OPENVPN_MANAGED:
            extra.append(f"{key} {value}".strip())
            continue
        first.setdefault(key, value)
    subnet = ""
    server = first.get("server", "")
    parts = server.split()
    if len(parts) >= 2:
        try:
            network = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
            subnet = f"{network.network_address}/{network.prefixlen}"
        except ValueError:
            subnet = parts[0]
    block = opts.get("block_outside_dns", True)
    if isinstance(block, str):
        block = block.lower() in ("1", "true", "on", "yes")
    return {
        "subnet": subnet or "10.8.0.0/24",
        "proto": first.get("proto", "udp"),
        "port": first.get("port", "1194"),
        "ncp_disable": "ncp-disable" in first or any(key == "ncp-disable" for key, _ in rows),
        "cipher": first.get("cipher", "AES-256-GCM"),
        "hash": first.get("auth", "SHA512"),
        "tls_auth": any(key == "tls-auth" for key, _ in rows),
        "block_outside_dns": bool(block),
        "additional_client": str(opts.get("additional_client", "")),
        "additional_server": "\n".join(extra),
    }


def render_openvpn_conf(fields: dict) -> tuple[str, dict, list[str]]:
    errors: list[str] = []
    subnet = _require_subnet(fields.get("subnet", ""), errors)
    port = _require_port(fields.get("port", ""), errors)
    proto = str(fields.get("proto", "udp")).strip().lower()
    if proto not in ("udp", "tcp"):
        errors.append("Сетевой протокол OpenVPN: udp или tcp")
    cipher = str(fields.get("cipher", "AES-256-GCM")).strip()
    digest = str(fields.get("hash", "SHA512")).strip()
    if cipher not in OPENVPN_CIPHERS:
        errors.append("Неизвестный шифр OpenVPN")
    if digest not in OPENVPN_HASHES:
        errors.append("Неизвестный хеш OpenVPN")
    if errors:
        return "", {}, errors
    network = ipaddress.ip_network(subnet, strict=False)
    ncp = "ncp-disable\n" if _flag(fields.get("ncp_disable")) else ""
    tls = "tls-auth /opt/amnezia/openvpn/ta.key 0\n" if _flag(fields.get("tls_auth")) else ""
    extra = str(fields.get("additional_server", "")).replace("\r", "").strip()
    if len(extra) > 4000:
        return "", {}, ["Дополнительные команды сервера длиннее 4000 символов"]
    client_extra = str(fields.get("additional_client", "")).replace("\r", "").strip()
    if len(client_extra) > 4000:
        return "", {}, ["Дополнительные команды клиента длиннее 4000 символов"]
    body = (
        f"port {port}\n"
        f"proto {proto}\n"
        "dev tun\n"
        "ca /opt/amnezia/openvpn/ca.crt\n"
        "cert /opt/amnezia/openvpn/AmneziaReq.crt\n"
        "key /opt/amnezia/openvpn/AmneziaReq.key\n"
        "dh /opt/amnezia/openvpn/dh.pem\n"
        f"server {network.network_address} {network.netmask}\n"
        "ifconfig-pool-persist ipp.txt\n"
        "duplicate-cn\n"
        "keepalive 10 120\n"
        f"{ncp}"
        f"cipher {cipher}\n"
        f"data-ciphers {cipher}\n"
        f"auth {digest}\n"
        "user nobody\n"
        "group nobody\n"
        "persist-key\n"
        "persist-tun\n"
        "crl-verify /opt/amnezia/openvpn/crl.pem\n"
        "status openvpn-status.log\n"
        "verb 1\n"
        "tls-server\n"
        "tls-version-min 1.2\n"
        f"{tls}"
    )
    if extra:
        body += extra + "\n"
    client_opts = {
        "block_outside_dns": _flag(fields.get("block_outside_dns")),
        "additional_client": client_extra,
    }
    return body, client_opts, []


def _flag(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "on", "yes")


def select_xray_inbound(config: dict) -> int:
    inbounds = config.get("inbounds") or []
    candidates = [i for i, item in enumerate(inbounds) if item.get("protocol", "vless") == "vless"]
    if not candidates:
        candidates = list(range(len(inbounds)))
    reality = [
        i for i in candidates
        if (inbounds[i].get("streamSettings") or {}).get("security") == "reality"
    ]
    if reality:
        return reality[0]
    if candidates:
        return candidates[0]
    raise ValueError("В конфиге XRay нет inbounds")


def _xhttp_mode_label(mode: str) -> str:
    mapping = {
        "": "Stream-one",
        "auto": "Stream-one",
        "stream-one": "Stream-one",
        "stream-up": "Stream-up",
        "packet-up": "Stream-up",
    }
    return mapping.get((mode or "").strip().lower(), mode or "Stream-one")


def _xhttp_mode_wire(label: str) -> str:
    text = (label or "").strip().lower()
    if text in ("stream-up", "stream-up"):
        return "stream-up"
    return "stream-one"


def xray_form_values(config: dict) -> dict:
    index = select_xray_inbound(config)
    inbound = config["inbounds"][index]
    stream = inbound.get("streamSettings") or {}
    network = stream.get("network") or "tcp"
    transport = {"xhttp": "xhttp", "kcp": "mkcp"}.get(network, "raw")
    security = stream.get("security") or "none"
    reality = stream.get("realitySettings") or {}
    tls = stream.get("tlsSettings") or {}
    xhttp = stream.get("xhttpSettings") or {}
    kcp = stream.get("kcpSettings") or {}
    site = ""
    dest = str(reality.get("dest") or "")
    if ":" in dest:
        site = dest.rsplit(":", 1)[0]
    elif dest:
        site = dest
    names = reality.get("serverNames") or []
    sni = names[0] if names else tls.get("serverName") or site
    alpn = tls.get("alpn") or ["h2"]
    if isinstance(alpn, list):
        alpn_text = ",".join(str(item) for item in alpn)
    else:
        alpn_text = str(alpn)
    clients = (inbound.get("settings") or {}).get("clients") or []
    flow = ""
    if clients and isinstance(clients[0], dict):
        flow = clients[0].get("flow") or ""
    fingerprint = reality.get("fingerprint") or tls.get("fingerprint") or "chrome"
    return {
        "port": str(inbound.get("port") or ""),
        "transport": transport,
        "security": security,
        "flow": flow if transport == "raw" else "",
        "sni": sni or XRAY_DEFAULT_SITE,
        "site": site or sni or XRAY_DEFAULT_SITE,
        "fingerprint": fingerprint if fingerprint in XRAY_FINGERPRINTS else "chrome",
        "alpn": alpn_text if alpn_text in XRAY_ALPN else "h2",
        "xhttp_mode": _xhttp_mode_label(str(xhttp.get("mode") or "")),
        "xhttp_host": xhttp.get("host") or XRAY_DEFAULT_SITE,
        "xhttp_path": xhttp.get("path") or "/",
        "mkcp_tti": str(kcp.get("tti") or "50"),
        "mkcp_uplink": str(kcp.get("uplinkCapacity") or "5"),
        "mkcp_downlink": str(kcp.get("downlinkCapacity") or "20"),
        "mkcp_mtu": str(kcp.get("mtu") or "1350"),
        "mkcp_cwnd": str(kcp.get("cwndMultiplier") if kcp.get("cwndMultiplier") not in (None, "") else "1"),
        "mkcp_window": "" if kcp.get("maxSendingWindow") in (None, "") else str(kcp.get("maxSendingWindow")),
    }


def _clamp_int(value: str, lo: int, hi: int, label: str, errors: list[str], default: int) -> int:
    raw = str(value or "").strip()
    if not raw:
        return default
    if not re.fullmatch(r"\d{1,10}", raw):
        errors.append(f"{label} должно быть целым числом")
        return default
    number = int(raw)
    if not lo <= number <= hi:
        errors.append(f"{label} должно быть от {lo} до {hi}")
        return default
    return number


def apply_xray_settings(config: dict, fields: dict) -> tuple[dict, list[str]]:
    errors: list[str] = []
    try:
        index = select_xray_inbound(config)
    except ValueError as exc:
        return config, [str(exc)]
    port = _require_port(fields.get("port", ""), errors)
    transport = str(fields.get("transport", "raw")).strip()
    security = str(fields.get("security", "none")).strip()
    if transport not in {item[0] for item in XRAY_TRANSPORTS}:
        errors.append("Неизвестный транспорт XRay")
    if security not in {item[0] for item in XRAY_SECURITY}:
        errors.append("Неизвестный режим безопасности XRay")
    if transport == "mkcp" and security == "reality":
        security = "none"
    flow = str(fields.get("flow", "")).strip()
    if flow and flow not in {item[0] for item in XRAY_FLOWS}:
        errors.append("Неизвестный flow XRay")
    sni = str(fields.get("sni", "")).strip() or XRAY_DEFAULT_SITE
    site = str(fields.get("site", "")).strip() or sni
    if not _HOST_RE.fullmatch(sni) or not _HOST_RE.fullmatch(site):
        errors.append("SNI и сайт Reality должны быть доменом или IP")
    fingerprint = str(fields.get("fingerprint", "chrome")).strip() or "chrome"
    if fingerprint not in XRAY_FINGERPRINTS:
        errors.append("Неизвестный fingerprint")
    alpn = str(fields.get("alpn", "h2")).strip() or "h2"
    if alpn not in XRAY_ALPN:
        errors.append("Неизвестный ALPN")
    path = str(fields.get("xhttp_path", "/") or "/").strip()
    host = str(fields.get("xhttp_host", "") or XRAY_DEFAULT_SITE).strip()
    if transport == "xhttp":
        if not _PATH_RE.fullmatch(path):
            errors.append("Путь XHTTP должен начинаться с /")
        if not _HOST_RE.fullmatch(host):
            errors.append("Host XHTTP должен быть доменом или IP")
    tti = _clamp_int(fields.get("mkcp_tti", ""), 10, 100, "TTI", errors, 50)
    uplink = _clamp_int(fields.get("mkcp_uplink", ""), 1, 100000, "uplinkCapacity", errors, 5)
    downlink = _clamp_int(fields.get("mkcp_downlink", ""), 1, 100000, "downlinkCapacity", errors, 20)
    mtu = _clamp_int(fields.get("mkcp_mtu", ""), 576, 1460, "mtu", errors, 1350)
    cwnd = _clamp_int(fields.get("mkcp_cwnd", ""), 1, 2147483647, "cwndMultiplier", errors, 1)
    window_raw = str(fields.get("mkcp_window", "")).strip()
    window = None
    if window_raw:
        window = _clamp_int(window_raw, mtu, 2147483647, "maxSendingWindow", errors, mtu)
    if errors:
        return config, errors

    updated = json.loads(json.dumps(config))
    inbound = updated["inbounds"][index]
    inbound["port"] = int(port)
    stream = dict(inbound.get("streamSettings") or {})
    stream["network"] = {"xhttp": "xhttp", "mkcp": "kcp"}.get(transport, "tcp")
    stream["security"] = security
    if transport == "xhttp":
        xhttp = dict(stream.get("xhttpSettings") or {})
        xhttp["host"] = host
        xhttp["path"] = path
        xhttp["mode"] = _xhttp_mode_wire(str(fields.get("xhttp_mode", "")))
        stream["xhttpSettings"] = xhttp
    else:
        stream.pop("xhttpSettings", None)
    if transport == "mkcp":
        kcp = {
            "tti": tti,
            "mtu": mtu,
            "uplinkCapacity": uplink,
            "downlinkCapacity": downlink,
            "cwndMultiplier": cwnd,
        }
        if window is not None:
            kcp["maxSendingWindow"] = window
        stream["kcpSettings"] = kcp
    else:
        stream.pop("kcpSettings", None)
    if security == "reality":
        old = (inbound.get("streamSettings") or {}).get("realitySettings") or {}
        private_key = old.get("privateKey") or fields.get("_private_key") or ""
        short_ids = old.get("shortIds") or ([fields["_short_id"]] if fields.get("_short_id") else [])
        if not private_key or not short_ids or not short_ids[0]:
            return config, ["Для Reality в контейнере нет пары ключей. Переустановите контейнер XRay."]
        stream["realitySettings"] = {
            "dest": f"{site}:443",
            "serverNames": [sni],
            "privateKey": private_key,
            "shortIds": short_ids,
            "fingerprint": fingerprint,
        }
        stream.pop("tlsSettings", None)
    elif security == "tls":
        stream.pop("realitySettings", None)
        stream["tlsSettings"] = {
            "serverName": sni,
            "alpn": [item.strip() for item in alpn.split(",") if item.strip()],
            "fingerprint": fingerprint,
            "certificates": [{
                "certificateFile": "/opt/amnezia/xray/tls_cert.pem",
                "keyFile": "/opt/amnezia/xray/tls_key.pem",
            }],
        }
    else:
        stream.pop("realitySettings", None)
        stream.pop("tlsSettings", None)
    inbound["streamSettings"] = stream
    use_flow = transport == "raw" and security in ("tls", "reality") and bool(flow)
    clients = (inbound.get("settings") or {}).setdefault("clients", [])
    for client in clients:
        if not isinstance(client, dict):
            continue
        if use_flow:
            client["flow"] = flow
        else:
            client.pop("flow", None)
    return updated, []


def default_xray_server(port: int, private_key: str, short_id: str, client_id: str,
                        site: str = XRAY_DEFAULT_SITE) -> dict:
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": int(port),
            "protocol": "vless",
            "settings": {
                "clients": [{"id": client_id, "flow": "xtls-rprx-vision"}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": f"{site}:443",
                    "serverNames": [site],
                    "privateKey": private_key,
                    "shortIds": [short_id],
                    "fingerprint": "chrome",
                },
            },
        }],
        "outbounds": [{"protocol": "freedom"}],
    }


def ipsec_form_values(ipsec_conf: str, ppp_options: str) -> dict:
    match = re.search(r"modecfgdns=([0-9.]+)\s*,\s*([0-9.]+)", ipsec_conf)
    dns = list(match.groups()) if match else ["", ""]
    if not dns[0]:
        found = re.findall(r"^ms-dns\s+([0-9.]+)", ppp_options, re.M)
        dns = (found + ["", ""])[:2]
    return {
        "primary_dns": dns[0] or "1.1.1.1",
        "secondary_dns": dns[1] or "1.0.0.1",
        "ports": "500/udp, 4500/udp",
    }


def apply_ipsec_dns(text: str, primary: str, secondary: str) -> str:
    text = re.sub(
        r"modecfgdns=[0-9.]+\s*,\s*[0-9.]+",
        f"modecfgdns={primary},{secondary}",
        text,
    )
    seen = {"n": 0}

    def _ms(match: re.Match) -> str:
        seen["n"] += 1
        return f"ms-dns {primary if seen['n'] == 1 else secondary}"

    return re.sub(r"ms-dns\s+[0-9.]+", _ms, text)


def _field(name, label, kind, value, **extra):
    item = {"name": name, "label": label, "type": kind, "value": value}
    item.update(extra)
    return item


def _select(name, label, value, options, **extra):
    return _field(
        name, label, "select", value,
        options=[{"value": opt[0], "label": opt[1]} if isinstance(opt, tuple) else {"value": opt, "label": opt}
                 for opt in options],
        **extra,
    )


def settings_form(protocol: str, values: dict) -> dict:
    """Схема формы редактора. protocol: awg, wireguard, openvpn, xray, ipsec."""
    if protocol in ("awg", "wireguard"):
        sections = [{
            "title": "Сервер",
            "fields": [
                _field("subnet", "Подсеть VPN", "text", values.get("subnet", "")),
                _field("port", "Порт", "number", values.get("port", ""), min=1, max=65535),
            ],
        }, {
            "title": "Клиент",
            "fields": [
                _field("mtu", "MTU", "number", values.get("mtu", "1376"), min=576, max=1500),
            ],
        }]
        if protocol == "awg":
            sections.append({
                "title": "Обфускация AmneziaWG",
                "fields": [
                    _field(key, label, "text", values.get(key, ""))
                    for key, label in (
                        ("Jc", "Jc — число мусорных пакетов"),
                        ("Jmin", "Jmin — минимальный размер"),
                        ("Jmax", "Jmax — максимальный размер"),
                        ("S1", "S1 — init packet junk"),
                        ("S2", "S2 — response packet junk"),
                        ("S3", "S3 — cookie reply junk"),
                        ("S4", "S4 — transport packet junk"),
                        ("H1", "H1 — init magic header"),
                        ("H2", "H2 — response magic header"),
                        ("H3", "H3 — underload magic header"),
                        ("H4", "H4 — transport magic header"),
                        ("I1", "I1 — special junk"),
                        ("I2", "I2"),
                        ("I3", "I3"),
                        ("I4", "I4"),
                        ("I5", "I5"),
                        ("HeaderProtectionKey", "HeaderProtectionKey"),
                        ("ContentPaddingAddition", "ContentPaddingAddition"),
                        ("RekeyAfterTime", "RekeyAfterTime"),
                        ("RekeyTimeout", "RekeyTimeout"),
                        ("RejectAfterTime", "RejectAfterTime"),
                        ("KeepaliveTimeout", "KeepaliveTimeout"),
                        ("MaxHandshakeAttempts", "MaxHandshakeAttempts"),
                    )
                ] + [
                    _select("RandomTrailers", "RandomTrailers", values.get("RandomTrailers") or "off", ["on", "off"]),
                    _select("DisableCookies", "DisableCookies", values.get("DisableCookies") or "off", ["on", "off"]),
                ],
            })
        return {"sections": sections, "notice": (
            "Смена порта пересоздаёт контейнер: опубликованный UDP-порт Docker должен совпасть "
            "со ListenPort. Смена обфускации AmneziaWG делает уже выданные конфиги нерабочими, "
            "их нужно отдать клиентам заново. Приватный ключ сервера и пиры сохраняются."
        )}

    if protocol == "openvpn":
        return {
            "notice": (
                "Смена порта или UDP/TCP пересоздаёт контейнер. Сертификаты сохраняются. "
                "Смена шифра, хеша или TLS-auth требует заново отдать файлы .ovpn."
            ),
            "sections": [{
                "title": "Сервер",
                "fields": [
                    _field("subnet", "Подсеть VPN", "text", values.get("subnet", "")),
                    _select("proto", "Сетевой протокол", values.get("proto", "udp"),
                            [("udp", "UDP"), ("tcp", "TCP")]),
                    _field("port", "Порт", "number", values.get("port", ""), min=1, max=65535),
                    _field("ncp_disable", "Отключить автосогласование шифрования", "checkbox",
                           "1" if values.get("ncp_disable") else ""),
                    _select("cipher", "Шифр", values.get("cipher", "AES-256-GCM"), OPENVPN_CIPHERS),
                    _select("hash", "Хеш", values.get("hash", "SHA512"), OPENVPN_HASHES),
                    _field("tls_auth", "TLS-auth", "checkbox", "1" if values.get("tls_auth") else ""),
                    _field("additional_server", "Дополнительные команды сервера", "textarea",
                           values.get("additional_server", "")),
                ],
            }, {
                "title": "Клиент",
                "fields": [
                    _field("block_outside_dns", "Блокировать DNS вне VPN", "checkbox",
                           "1" if values.get("block_outside_dns") else ""),
                    _field("additional_client", "Дополнительные команды клиента", "textarea",
                           values.get("additional_client", "")),
                ],
            }],
        }

    if protocol == "xray":
        return {
            "notice": (
                "Смена порта пересоздаёт контейнер. Смена транспорта, Reality, SNI или flow "
                "делает уже выданные ссылки нерабочими. Ключ Reality и short id не меняются."
            ),
            "sections": [{
                "title": "Соединение",
                "fields": [
                    _field("port", "Порт", "number", values.get("port", ""), min=1, max=65535,
                           show=""),
                    _select("transport", "Транспорт", values.get("transport", "raw"), XRAY_TRANSPORTS),
                    _select("security", "Безопасность", values.get("security", "reality"), XRAY_SECURITY),
                    _select("flow", "Flow", values.get("flow", ""), XRAY_FLOWS, show_transport="raw"),
                    _field("sni", "Server Name (SNI)", "text", values.get("sni", ""),
                           show_security="tls reality"),
                    _field("site", "Сайт для Reality (dest)", "text", values.get("site", ""),
                           show_security="reality"),
                    _select("fingerprint", "Fingerprint", values.get("fingerprint", "chrome"),
                            XRAY_FINGERPRINTS, show_security="tls reality"),
                    _select("alpn", "ALPN", values.get("alpn", "h2"), XRAY_ALPN, show_security="tls"),
                ],
            }, {
                "title": "XHTTP",
                "show_transport": "xhttp",
                "fields": [
                    _select("xhttp_mode", "Режим", values.get("xhttp_mode", "Stream-one"), XRAY_XHTTP_MODES),
                    _field("xhttp_host", "Host", "text", values.get("xhttp_host", "")),
                    _field("xhttp_path", "Path", "text", values.get("xhttp_path", "/")),
                ],
            }, {
                "title": "mKCP",
                "show_transport": "mkcp",
                "fields": [
                    _field("mkcp_tti", "TTI", "number", values.get("mkcp_tti", "50")),
                    _field("mkcp_uplink", "uplinkCapacity", "number", values.get("mkcp_uplink", "5")),
                    _field("mkcp_downlink", "downlinkCapacity", "number", values.get("mkcp_downlink", "20")),
                    _field("mkcp_mtu", "mtu", "number", values.get("mkcp_mtu", "1350")),
                    _field("mkcp_cwnd", "cwndMultiplier", "number", values.get("mkcp_cwnd", "1")),
                    _field("mkcp_window", "maxSendingWindow", "text", values.get("mkcp_window", "")),
                ],
            }],
        }

    return {
        "notice": (
            "Порты IKEv2 фиксированы: 500/udp и 4500/udp, как в Amnezia. "
            "В клиенте Amnezia у этого протокола нет редактора соединения, "
            "здесь меняются только DNS, которые получают клиенты."
        ),
        "sections": [{
            "title": "IKEv2 / IPsec",
            "fields": [
                _field("ports", "Порты", "text", values.get("ports", ""), readonly=True),
                _field("primary_dns", "Основной DNS", "text", values.get("primary_dns", "")),
                _field("secondary_dns", "Второй DNS", "text", values.get("secondary_dns", "")),
            ],
        }],
    }
