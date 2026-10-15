import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me-in-production")
    SSH_TIMEOUT = 10
    DOCKER_CMD_TIMEOUT = 30
    CONTAINER_INSTALL_TIMEOUT = 900

    # Имена контейнеров — ровно как в amnezia-client
    # (client/core/utils/containers/containerUtils.cpp::containerToString).
    # Контейнеры показываются на главной всегда, даже если не созданы.
    AMNEZIA_CONTAINERS = [
        "amnezia-awg2",          # AmneziaWG 2 / 3.1 (текущая версия)
        "amnezia-awg",           # AmneziaWG legacy (1.0 / 1.5)
        "amnezia-wireguard",
        "amnezia-openvpn",
        "amnezia-openvpn-cloak",
        "amnezia-shadowsocks",
        "amnezia-xray",
        "amnezia-ssxray",
        "amnezia-ipsec",
        "amnezia-dns",
        "amnezia-sftp",
        "amnezia-socks5proxy",
        "amnezia-mtproxy",
        "amnezia-telemt",
        "amnezia-tproxy",
        "amnezia-torwebsite",
    ]

    CONTAINER_LABELS = {
        "amnezia-awg2": "AmneziaWG",
        "amnezia-awg": "AmneziaWG (legacy)",
        "amnezia-wireguard": "WireGuard",
        "amnezia-openvpn": "OpenVPN",
        "amnezia-openvpn-cloak": "OpenVPN over Cloak",
        "amnezia-shadowsocks": "OpenVPN over Shadowsocks",
        "amnezia-xray": "XRay",
        "amnezia-ssxray": "Shadowsocks (XRay)",
        "amnezia-ipsec": "IKEv2 / IPsec",
        "amnezia-dns": "AmneziaDNS",
        "amnezia-torwebsite": "Сайт в сети Tor",
        "amnezia-sftp": "SFTP",
        "amnezia-socks5proxy": "SOCKS5 proxy",
        "amnezia-mtproxy": "MTProxy (Telegram)",
        "amnezia-telemt": "Telemt (Telegram)",
        "amnezia-tproxy": "TProxy (Telegram WEB)",
    }

    # Протоколы, которые панель умеет СОЗДАВАТЬ в формате amnezia-client
    # (Dockerfile + configure/start-скрипты из client/server_scripts).
    # Такие контейнеры потом видит и приложение AmneziaVPN.
    # Legacy AmneziaWG, Cloak и OpenVPN-over-Shadowsocks клиент больше не ставит.
    CREATABLE_PROTOCOLS = {
        "awg2": {
            "container": "amnezia-awg2",
            "label": "AmneziaWG (v3.1)",
            "group": "vpn",
            "default_port": 55424,
            "port_type": "udp",
            "transport_choice": False,
            "fixed_ports": "",
            "create_fields": [],
        },
        "wireguard": {
            "container": "amnezia-wireguard",
            "label": "WireGuard",
            "group": "vpn",
            "default_port": 51820,
            "port_type": "udp",
            "transport_choice": False,
            "fixed_ports": "",
            "create_fields": [],
        },
        "xray": {
            "container": "amnezia-xray",
            "label": "XRay (VLESS Reality)",
            "group": "vpn",
            "default_port": 443,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "",
            "create_fields": [],
        },
        "openvpn": {
            "container": "amnezia-openvpn",
            "label": "OpenVPN",
            "group": "vpn",
            "default_port": 1194,
            "port_type": "udp",
            "transport_choice": True,
            "fixed_ports": "",
            "create_fields": [],
        },
        "ipsec": {
            "container": "amnezia-ipsec",
            "label": "IKEv2 / IPsec",
            "group": "vpn",
            "default_port": 500,
            "port_type": "udp",
            "transport_choice": False,
            "fixed_ports": "500/udp и 4500/udp",
            "create_fields": [],
        },
        "dns": {
            "container": "amnezia-dns",
            "label": "AmneziaDNS",
            "group": "service",
            "default_port": 53,
            "port_type": "udp",
            "transport_choice": False,
            "fixed_ports": "172.29.172.254 в сети Docker",
            "create_fields": [],
        },
        "sftp": {
            "container": "amnezia-sftp",
            "label": "SFTP",
            "group": "service",
            "default_port": 222,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "",
            "create_fields": ["username", "password"],
        },
        "socks5": {
            "container": "amnezia-socks5proxy",
            "label": "SOCKS5 proxy",
            "group": "service",
            "default_port": 38080,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "",
            "create_fields": ["username", "password"],
        },
        "mtproxy": {
            "container": "amnezia-mtproxy",
            "label": "MTProxy (Telegram)",
            "group": "service",
            "default_port": 443,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "",
            "create_fields": ["public_host", "transport_mode", "tls_domain"],
        },
        "telemt": {
            "container": "amnezia-telemt",
            "label": "Telemt (Telegram)",
            "group": "service",
            "default_port": 443,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "",
            "create_fields": ["public_host", "transport_mode", "tls_domain"],
        },
        "tproxy": {
            "container": "amnezia-tproxy",
            "label": "TProxy (Telegram WEB)",
            "group": "service",
            "default_port": 443,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "80/tcp и 443/tcp",
            "create_fields": ["hostname", "acme_email"],
        },
        "tor": {
            "container": "amnezia-torwebsite",
            "label": "Сайт в сети Tor",
            "group": "service",
            "default_port": 80,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "порты не публикуются",
            "create_fields": [],
        },
    }

    # Контейнеры, у которых есть редактор настроек соединения.
    SETTINGS_CONTAINERS = {
        "amnezia-awg2",
        "amnezia-awg",
        "amnezia-wireguard",
        "amnezia-openvpn",
        "amnezia-xray",
        "amnezia-ipsec",
        "amnezia-dns",
        "amnezia-sftp",
        "amnezia-socks5proxy",
        "amnezia-mtproxy",
        "amnezia-telemt",
        "amnezia-tproxy",
        "amnezia-torwebsite",
    }

    # Контейнер → тип управления клиентами
    CLIENT_PROTOCOLS = {
        "amnezia-awg2": "wireguard",
        "amnezia-awg": "wireguard",
        "amnezia-wireguard": "wireguard",
        "amnezia-openvpn": "openvpn",
        "amnezia-xray": "xray",
    }

    # DNS для клиентских конфигов (дефолты amnezia-client)
    PRIMARY_DNS = os.environ.get("AMNEZIA_PRIMARY_DNS", "1.1.1.1")
    SECONDARY_DNS = os.environ.get("AMNEZIA_SECONDARY_DNS", "1.0.0.1")
    AMNEZIA_DNS_IP = "172.29.172.254"
