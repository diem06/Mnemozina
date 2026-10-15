"""Установка и настройки служб Amnezia: DNS, SFTP, SOCKS5, MTProxy, Telemt, TProxy, Tor."""
from __future__ import annotations

import re
import secrets
import string

SFTP_USER = "sftp_user"
SOCKS_USER = "proxy_user"
MTPROXY_DOMAIN = "googletagmanager.com"
TELEMT_USER = "amnezia"

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_EMAIL = re.compile(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_DNS_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


def random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _port(value: str, errors: list[str], label: str = "Порт") -> str:
    return _int_range(value, errors, label, 1, 65535, "")


def _int_range(value, errors: list[str], label: str, low: int, high: int, default: str) -> str:
    raw = default if value in (None, "") else str(value).strip()
    try:
        number = int(raw)
    except ValueError:
        errors.append(f"{label} должен быть числом от {low} до {high}")
        return ""
    if not low <= number <= high:
        errors.append(f"{label} должен быть числом от {low} до {high}")
        return ""
    return str(number)


def _flag(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "on", "yes")


def parse_meta(text: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        meta[key.strip()] = value
    return meta


def domain_hex(domain: str) -> str:
    return domain.encode().hex()


def proxy_client_secret(base_hex: str, mode: str, domain: str) -> str:
    if not base_hex:
        return ""
    if mode == "faketls":
        return "ee" + base_hex.lower() + domain_hex(domain or MTPROXY_DOMAIN)
    return "dd" + base_hex.lower()


def telegram_links(host: str, port: str, client_secret: str) -> tuple[str, str]:
    if not (host and port and client_secret):
        return "", ""
    query = f"server={host}&port={port}&secret={client_secret}"
    return f"tg://proxy?{query}", f"https://t.me/proxy?{query}"


def webproxy_links(host: str, secret: str) -> tuple[str, str]:
    if not (host and secret):
        return "", ""
    return (
        f"tg://webproxy?server={host}&secret={secret}",
        f"https://t.me/webproxy?server={host}&secret={secret}",
    )


def _secrets_list(text: str, errors: list[str]) -> list[str]:
    items = []
    for raw in re.split(r"[\s,]+", str(text or "").strip()):
        if not raw:
            continue
        if not _HEX32.fullmatch(raw):
            errors.append(f"Дополнительный секрет {raw} должен быть 32 hex-символа")
            continue
        items.append(raw.lower())
    return items


def _tag(value: str, errors: list[str]) -> str:
    tag = str(value or "").strip()
    if tag and not _HEX32.fullmatch(tag):
        errors.append("Тег канала должен быть пустым или содержать 32 hex-символа")
    return tag.lower()


def validate_proxy_fields(fields: dict, kind: str) -> tuple[dict, list[str]]:
    errors: list[str] = []
    port = _port(fields.get("port", ""), errors)
    mode = str(fields.get("transport_mode", "standard")).strip() or "standard"
    if mode not in ("standard", "faketls"):
        errors.append("Режим транспорта: standard или faketls")
    domain = str(fields.get("tls_domain", "")).strip() or MTPROXY_DOMAIN
    if not _HOST.fullmatch(domain):
        errors.append("Домен FakeTLS должен быть именем хоста")
    public_host = str(fields.get("public_host", "")).strip()
    if public_host and not _HOST.fullmatch(public_host):
        errors.append("Публичный хост должен быть доменом или IP")
    tag = _tag(fields.get("tag", ""), errors)
    extra = _secrets_list(fields.get("additional_secrets", ""), errors)
    cleaned = {
        "port": port,
        "transport_mode": mode,
        "tls_domain": domain,
        "public_host": public_host,
        "tag": tag,
        "additional_secrets": extra,
    }
    if kind == "mtproxy":
        workers_mode = str(fields.get("workers_mode", "auto")).strip() or "auto"
        if workers_mode not in ("auto", "manual"):
            errors.append("Режим воркеров: auto или manual")
        if mode == "faketls" and workers_mode == "auto":
            workers = "0"
        elif workers_mode == "auto":
            workers = "2"
        else:
            workers = _int_range(fields.get("workers", "2"), errors, "Число воркеров", 0, 19, "2")
        nat = _flag(fields.get("nat_enabled"))
        internal = str(fields.get("nat_internal", "")).strip()
        external = str(fields.get("nat_external", "")).strip()
        if nat and (not _HOST.fullmatch(internal) or not _HOST.fullmatch(external)):
            errors.append("Для NAT укажите внутренний и внешний IP")
        cleaned.update({
            "workers_mode": workers_mode,
            "workers": workers or "2",
            "nat_enabled": nat,
            "nat_internal": internal,
            "nat_external": external,
        })
    else:
        cleaned.update({
            "mask": _flag(fields.get("mask")),
            "tls_emulation": _flag(fields.get("tls_emulation")),
            "use_middle_proxy": _flag(fields.get("use_middle_proxy")),
            "user_name": str(fields.get("user_name", "")).strip() or TELEMT_USER,
            "nat_external": str(fields.get("nat_external", "")).strip(),
        })
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", cleaned["user_name"]):
            errors.append("Имя пользователя Telemt: буквы, цифры, _ и -")
    return cleaned, errors


def mtproxy_env(cleaned: dict, secret: str, regenerate: bool) -> dict[str, str]:
    workers = cleaned["workers"]
    return {
        "$MTPROXY_PORT": cleaned["port"],
        "$MTPROXY_SECRET": "" if regenerate else secret,
        "$MTPROXY_REGENERATE_SECRET": "1" if regenerate else "0",
        "$MTPROXY_TAG": cleaned["tag"],
        "$MTPROXY_TRANSPORT_MODE": cleaned["transport_mode"],
        "$MTPROXY_TLS_DOMAIN": cleaned["tls_domain"],
        "$MTPROXY_PUBLIC_HOST": cleaned["public_host"],
        "$MTPROXY_ADDITIONAL_SECRETS": ",".join(cleaned["additional_secrets"]),
        "$MTPROXY_WORKERS_MODE": cleaned["workers_mode"],
        "$MTPROXY_WORKERS": workers,
        "$MTPROXY_NAT_ENABLED": "1" if cleaned["nat_enabled"] else "0",
        "$MTPROXY_NAT_INTERNAL_IP": cleaned["nat_internal"],
        "$MTPROXY_NAT_EXTERNAL_IP": cleaned["nat_external"],
    }


def telemt_env(cleaned: dict, secret: str, regenerate: bool) -> dict[str, str]:
    faketls = cleaned["transport_mode"] == "faketls"
    return {
        "$TELEMT_TOML_SECURE": "false" if faketls else "true",
        "$TELEMT_TOML_TLS": "true" if faketls else "false",
        "$TELEMT_PORT": cleaned["port"],
        "$TELEMT_SECRET": "" if regenerate else secret,
        "$TELEMT_REGENERATE_SECRET": "1" if regenerate else "0",
        "$TELEMT_TAG": cleaned["tag"],
        "$TELEMT_TLS_DOMAIN": cleaned["tls_domain"],
        "$TELEMT_PUBLIC_HOST": cleaned["public_host"],
        "$TELEMT_USER_NAME": cleaned["user_name"],
        "$TELEMT_USE_MIDDLE_PROXY": "true" if cleaned["use_middle_proxy"] else "false",
        "$TELEMT_MASK": "true" if cleaned["mask"] else "false",
        "$TELEMT_TLS_EMULATION": "true" if cleaned["tls_emulation"] else "false",
        "$TELEMT_ADDITIONAL_SECRETS": ",".join(cleaned["additional_secrets"]),
        "$TELEMT_MIDDLE_PROXY_NAT_IP": cleaned["nat_external"],
    }


def mtproxy_values(meta_text: str, secret: str, server_host: str) -> dict:
    meta = parse_meta(meta_text)
    mode = meta.get("mode") or "standard"
    domain = meta.get("domain") or MTPROXY_DOMAIN
    host = meta.get("public_host") or server_host
    port = meta.get("port") or "443"
    client_secret = proxy_client_secret(secret.strip(), mode, domain)
    tg_link, tme_link = telegram_links(host, port, client_secret)
    return {
        "port": port,
        "transport_mode": mode,
        "tls_domain": domain,
        "public_host": meta.get("public_host", ""),
        "tag": meta.get("tag", ""),
        "additional_secrets": (meta.get("additional") or "").replace(",", "\n"),
        "workers_mode": meta.get("workers_mode") or "auto",
        "workers": meta.get("workers") or "2",
        "nat_enabled": meta.get("nat_enabled") == "1",
        "nat_internal": meta.get("nat_internal", ""),
        "nat_external": meta.get("nat_external", ""),
        "tg_link": tg_link,
        "tme_link": tme_link,
        "secret": secret.strip(),
    }


def telemt_values(toml: str, secret: str, server_host: str) -> dict:
    def quoted(key: str) -> str:
        match = re.search(rf'(?m)^{re.escape(key)} = "([^"]*)"', toml)
        return match.group(1) if match else ""

    def boolean(key: str, default: bool = False) -> bool:
        match = re.search(rf"(?m)^{re.escape(key)} = (true|false)", toml)
        if not match:
            return default
        return match.group(1) == "true"

    tls = boolean("tls")
    mode = "faketls" if tls else "standard"
    domain = quoted("tls_domain") or MTPROXY_DOMAIN
    public_host = quoted("public_host")
    port_match = re.search(r"(?m)^public_port = (\d+)", toml)
    port = port_match.group(1) if port_match else "443"
    users = _toml_users(toml)
    user_name = users[0][0] if users else TELEMT_USER
    extra = [value for name, value in users if name.startswith("extra_")]
    host = public_host or server_host
    client_secret = proxy_client_secret(secret.strip(), mode, domain)
    tg_link, tme_link = telegram_links(host, port, client_secret)
    return {
        "port": port,
        "transport_mode": mode,
        "tls_domain": domain,
        "public_host": public_host,
        "tag": quoted("ad_tag"),
        "additional_secrets": "\n".join(extra),
        "mask": boolean("mask", True),
        "tls_emulation": boolean("tls_emulation"),
        "use_middle_proxy": boolean("use_middle_proxy", True),
        "user_name": user_name,
        "nat_external": quoted("middle_proxy_nat_ip"),
        "tg_link": tg_link,
        "tme_link": tme_link,
        "secret": secret.strip(),
    }


def _toml_users(toml: str) -> list[tuple[str, str]]:
    section = ""
    users = []
    for line in toml.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
            continue
        if section != "[access.users]":
            continue
        match = re.fullmatch(r'([A-Za-z0-9_-]+) = "([0-9a-fA-F]{32})"', stripped)
        if match:
            users.append((match.group(1), match.group(2).lower()))
    return users


def tproxy_values(meta_text: str, secret: str) -> dict:
    meta = parse_meta(meta_text)
    host = meta.get("hostname", "")
    tg_link, tme_link = webproxy_links(host, secret.strip())
    return {
        "hostname": host,
        "acme_email": meta.get("email", ""),
        "carrier_mode": meta.get("carrier") or "https",
        "workers": meta.get("workers") or "1",
        "http_port": meta.get("http_port") or "80",
        "https_port": meta.get("https_port") or "443",
        "tg_link": tg_link,
        "tme_link": tme_link,
        "secret": secret.strip(),
    }


def validate_tproxy(fields: dict) -> tuple[dict, list[str]]:
    errors: list[str] = []
    host = str(fields.get("hostname", "")).strip().lower()
    email = str(fields.get("acme_email", "")).strip()
    if not _DNS_HOST.fullmatch(host):
        errors.append("Hostname: строчные буквы, цифры, точки и дефисы")
    if not _EMAIL.fullmatch(email):
        errors.append("Нужен корректный email для сертификата")
    carrier = str(fields.get("carrier_mode", "https")).strip() or "https"
    if carrier not in ("https", "https-lanes", "websocket", "websocket-lanes"):
        errors.append("Неизвестный режим carrier")
    workers = _int_range(fields.get("workers", "1"), errors, "Воркеры", 1, 32, "1")
    http_port = _port(fields.get("http_port", "80") or "80", errors, "Порт HTTP")
    https_port = _port(fields.get("https_port", "443") or "443", errors, "Порт HTTPS")
    return {
        "hostname": host,
        "acme_email": email,
        "carrier_mode": carrier,
        "workers": workers or "1",
        "http_port": http_port or "80",
        "https_port": https_port or "443",
    }, errors


def tproxy_env(cleaned: dict, secret: str, regenerate: bool) -> dict[str, str]:
    return {
        "$TPROXY_SECRET": "" if regenerate else secret,
        "$TPROXY_REGENERATE_SECRET": "1" if regenerate else "0",
        "$TPROXY_HOSTNAME": cleaned["hostname"],
        "$TPROXY_ACME_EMAIL": cleaned["acme_email"],
        "$TPROXY_HTTPS_PORT": cleaned["https_port"],
        "$TPROXY_HTTP_PORT": cleaned["http_port"],
        "$TPROXY_CARRIER_MODE": cleaned["carrier_mode"],
        "$TPROXY_WORKERS": cleaned["workers"],
    }


def socks_env(port: str, username: str, password: str) -> dict[str, str]:
    if username:
        user_line = f"users {username}:CL:{password}"
        auth = "strong"
    else:
        user_line = ""
        auth = "none"
    return {
        "$SOCKS5_PROXY_PORT": str(port),
        "$SOCKS5_USER": user_line,
        "$SOCKS5_AUTH_TYPE": auth,
    }


def parse_socks(config: str) -> dict:
    user = password = ""
    match = re.search(r"users (\w+):CL:(\w+)", config)
    if match:
        user, password = match.group(1), match.group(2)
    port_match = re.search(r"socks -p(\d+)", config)
    return {
        "port": port_match.group(1) if port_match else "38080",
        "username": user,
        "password": password,
    }


def parse_sftp_cmd(cmd: str) -> tuple[str, str]:
    match = re.search(r"([A-Za-z0-9_-]+):([A-Za-z0-9_-]+):::upload", cmd or "")
    if not match:
        return "", ""
    return match.group(1), match.group(2)


def validate_login(username: str, password: str, allow_empty: bool) -> tuple[str, str, list[str]]:
    errors: list[str] = []
    user = str(username or "").strip()
    secret = str(password or "").strip()
    if allow_empty and not user and not secret:
        return "", "", []
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", user):
        errors.append("Логин: буквы, цифры, _ и -, до 32 символов")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", secret):
        errors.append("Пароль: 8–64 символа, буквы, цифры, _ и -")
    return user, secret, errors


def _field(name, label, kind, value, **extra):
    item = {"name": name, "label": label, "type": kind, "value": value}
    item.update(extra)
    return item


def _select(name, label, value, options, **extra):
    return _field(
        name, label, "select", value,
        options=[{"value": item[0], "label": item[1]} if isinstance(item, tuple) else {"value": item, "label": item}
                 for item in options],
        **extra,
    )


def service_form(kind: str, values: dict) -> dict:
    if kind == "dns":
        return {
            "readonly": True,
            "notice": "AmneziaDNS слушает 172.29.172.254 в сети Docker amnezia-dns-net. Отдельных параметров соединения у него нет.",
            "sections": [{"title": "DNS", "fields": [
                _field("address", "Адрес", "text", "172.29.172.254", readonly=True),
            ]}],
        }
    if kind == "tor":
        return {
            "readonly": True,
            "notice": "Onion-адрес появляется через несколько минут после запуска. Открывайте его в Tor Browser. В WordPress укажите этот адрес как домен.",
            "sections": [{"title": "Сайт", "fields": [
                _field("hostname", "Адрес сайта", "text", values.get("hostname", ""), readonly=True),
            ]}],
        }
    if kind == "sftp":
        return {
            "notice": "Смена порта, логина или пароля пересоздаёт контейнер. Каталог upload при этом не сохраняется: образ Amnezia не подключает отдельный том.",
            "sections": [{"title": "Доступ", "fields": [
                _field("host", "Хост", "text", values.get("host", ""), readonly=True),
                _field("port", "Порт", "number", values.get("port", "222"), min=1, max=65535),
                _field("username", "Логин", "text", values.get("username", "")),
                _field("password", "Пароль", "text", values.get("password", "")),
            ]}],
        }
    if kind == "socks5":
        return {
            "notice": "Пустые логин и пароль отключают авторизацию. Смена порта пересоздаёт контейнер.",
            "sections": [{"title": "SOCKS5", "fields": [
                _field("port", "Порт", "number", values.get("port", "38080"), min=1, max=65535),
                _field("username", "Логин", "text", values.get("username", "")),
                _field("password", "Пароль", "text", values.get("password", "")),
            ]}],
        }
    if kind == "tproxy":
        return {
            "notice": "Нужна DNS-запись A на этот сервер и свободные порты HTTP и HTTPS. Классические ссылки MTProxy здесь не работают.",
            "sections": [
                {"title": "Подключение", "fields": [
                    _field("tg_link", "Ссылка tg://", "text", values.get("tg_link", ""), readonly=True),
                    _field("tme_link", "Ссылка t.me", "text", values.get("tme_link", ""), readonly=True),
                ]},
                {"title": "Параметры", "fields": [
                    _field("hostname", "Hostname", "text", values.get("hostname", "")),
                    _field("acme_email", "Email ACME", "text", values.get("acme_email", "")),
                    _select("carrier_mode", "Режим", values.get("carrier_mode", "https"),
                            ["https", "https-lanes", "websocket", "websocket-lanes"]),
                    _field("workers", "Воркеры MTProxy", "number", values.get("workers", "1"), min=1, max=32),
                    _field("http_port", "Порт HTTP", "number", values.get("http_port", "80"), min=1, max=65535),
                    _field("https_port", "Порт HTTPS", "number", values.get("https_port", "443"), min=1, max=65535),
                ]},
            ],
        }
    proxy_fields = [
        _field("tg_link", "Ссылка tg://", "text", values.get("tg_link", ""), readonly=True),
        _field("tme_link", "Ссылка t.me", "text", values.get("tme_link", ""), readonly=True),
        _field("public_host", "Публичный хост", "text", values.get("public_host", "")),
        _field("port", "Порт", "number", values.get("port", "443"), min=1, max=65535),
        _field("tag", "Тег канала", "text", values.get("tag", "")),
        _select("transport_mode", "Режим", values.get("transport_mode", "standard"),
                [("standard", "MTProto"), ("faketls", "FakeTLS")]),
        _field("tls_domain", "Домен FakeTLS", "text", values.get("tls_domain", MTPROXY_DOMAIN)),
        _field("additional_secrets", "Дополнительные секреты", "textarea", values.get("additional_secrets", "")),
    ]
    if kind == "mtproxy":
        proxy_fields += [
            _select("workers_mode", "Воркеры", values.get("workers_mode", "auto"),
                    [("auto", "Авто"), ("manual", "Вручную")]),
            _field("workers", "Число воркеров", "number", values.get("workers", "2"), min=0, max=19),
            _field("nat_enabled", "Сервер за NAT", "checkbox", "1" if values.get("nat_enabled") else ""),
            _field("nat_internal", "Внутренний IP", "text", values.get("nat_internal", "")),
            _field("nat_external", "Внешний IP", "text", values.get("nat_external", "")),
        ]
        notice = "Смена порта пересоздаёт контейнер. Смена домена FakeTLS меняет секрет в ссылке."
    else:
        proxy_fields += [
            _field("user_name", "Имя в конфиге", "text", values.get("user_name", TELEMT_USER)),
            _field("mask", "Маскировка", "checkbox", "1" if values.get("mask", True) else ""),
            _field("tls_emulation", "Эмуляция TLS", "checkbox", "1" if values.get("tls_emulation") else ""),
            _field("use_middle_proxy", "Middle proxy", "checkbox", "1" if values.get("use_middle_proxy", True) else ""),
            _field("nat_external", "Публичный IP вручную", "text", values.get("nat_external", "")),
        ]
        notice = "Смена порта пересоздаёт контейнер. Секрет сохраняется, ссылка меняется вместе с хостом, портом и FakeTLS."
    return {
        "notice": notice,
        "sections": [
            {"title": "Подключение", "fields": proxy_fields[:2]},
            {"title": "Параметры", "fields": proxy_fields[2:]},
        ],
    }
