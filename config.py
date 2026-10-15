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
            "default_port": 55424,
            "port_type": "udp",
            "transport_choice": False,
            "fixed_ports": "",
        },
        "wireguard": {
            "container": "amnezia-wireguard",
            "label": "WireGuard",
            "default_port": 51820,
            "port_type": "udp",
            "transport_choice": False,
            "fixed_ports": "",
        },
        "xray": {
            "container": "amnezia-xray",
            "label": "XRay (VLESS Reality)",
            "default_port": 443,
            "port_type": "tcp",
            "transport_choice": False,
            "fixed_ports": "",
        },
        "openvpn": {
            "container": "amnezia-openvpn",
            "label": "OpenVPN",
            "default_port": 1194,
            "port_type": "udp",
            "transport_choice": True,
            "fixed_ports": "",
        },
        "ipsec": {
            "container": "amnezia-ipsec",
            "label": "IKEv2 / IPsec",
            "default_port": 500,
            "port_type": "udp",
            "transport_choice": False,
            "fixed_ports": "500/udp и 4500/udp",
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
