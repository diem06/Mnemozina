"""Настройки соединения: разбор и запись без SSH."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from connection_settings import (
    apply_ipsec_dns,
    apply_wg_settings,
    apply_xray_settings,
    default_xray_server,
    openvpn_form_values,
    parse_wg_conf,
    render_openvpn_conf,
    settings_form,
    xray_form_values,
)
from container_manager import ContainerManager


AWG_CONF = """[Interface]
PrivateKey = server-private
Address = 10.8.1.0/24
ListenPort = 55424
Jc = 4
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = aaaa
RandomTrailers = on
DisableCookies = on
# I1 = <r 2>

[Peer]
PublicKey = client-public
PresharedKey = psk
AllowedIPs = 10.8.1.2/32
"""


class WgSettingsTest(unittest.TestCase):
    def test_roundtrip_keeps_peers_and_private_key(self):
        fields = {
            "subnet": "10.9.0.0/24",
            "port": "40000",
            "mtu": "1280",
            "Jc": "5", "Jmin": "10", "Jmax": "50",
            "S1": "12", "S2": "12", "S3": "12", "S4": "12",
            "H1": "11", "H2": "12", "H3": "13", "H4": "14",
            "I1": "<r 2>", "I2": "", "I3": "", "I4": "", "I5": "",
            "HeaderProtectionKey": "aaaa",
            "ContentPaddingAddition": "",
            "RekeyAfterTime": "100-120",
            "RekeyTimeout": "",
            "RejectAfterTime": "",
            "KeepaliveTimeout": "",
            "MaxHandshakeAttempts": "",
            "RandomTrailers": "on",
            "DisableCookies": "off",
        }
        rendered, errors = apply_wg_settings(AWG_CONF, fields, awg=True)
        self.assertEqual(errors, [])
        interface, peers = parse_wg_conf(rendered)
        self.assertEqual(interface["PrivateKey"], "server-private")
        self.assertEqual(interface["Address"], "10.9.0.0/24")
        self.assertEqual(interface["ListenPort"], "40000")
        self.assertEqual(interface["Jc"], "5")
        self.assertEqual(interface["H4"], "14")
        self.assertEqual(interface["DisableCookies"], "off")
        self.assertEqual(interface["I1"], "<r 2>")
        self.assertEqual(peers[0]["PublicKey"], "client-public")
        self.assertEqual(peers[0]["AllowedIPs"], "10.8.1.2/32")

    def test_duplicate_magic_headers_rejected(self):
        fields = {
            "subnet": "10.8.1.0/24", "port": "55424", "mtu": "1376",
            "H1": "1", "H2": "1", "H3": "3", "H4": "4",
            "Jc": "4", "Jmin": "10", "Jmax": "50",
            "RandomTrailers": "on", "DisableCookies": "on",
        }
        rendered, errors = apply_wg_settings(AWG_CONF, fields, awg=True)
        self.assertTrue(errors)
        self.assertIn("ListenPort = 55424", rendered)


class OpenVpnSettingsTest(unittest.TestCase):
    def test_render_and_parse(self):
        rendered, opts, errors = render_openvpn_conf({
            "subnet": "10.8.0.0/24",
            "proto": "tcp",
            "port": "443",
            "ncp_disable": "1",
            "cipher": "AES-256-GCM",
            "hash": "SHA512",
            "tls_auth": "1",
            "block_outside_dns": "",
            "additional_server": "push \"route 10.1.0.0 255.255.0.0\"",
            "additional_client": "explicit-exit-notify",
        })
        self.assertEqual(errors, [])
        self.assertIn("proto tcp\n", rendered)
        self.assertIn("port 443\n", rendered)
        self.assertIn("ncp-disable\n", rendered)
        self.assertIn("server 10.8.0.0 255.255.255.0\n", rendered)
        self.assertIn("tls-auth /opt/amnezia/openvpn/ta.key 0\n", rendered)
        self.assertFalse(opts["block_outside_dns"])
        self.assertEqual(opts["additional_client"], "explicit-exit-notify")
        values = openvpn_form_values(rendered, opts)
        self.assertEqual(values["proto"], "tcp")
        self.assertEqual(values["subnet"], "10.8.0.0/24")
        self.assertIn("push", values["additional_server"])
        self.assertTrue(values["ncp_disable"])
        self.assertTrue(values["tls_auth"])


class XraySettingsTest(unittest.TestCase):
    def setUp(self):
        self.config = {
            "inbounds": [
                {
                    "tag": "plain",
                    "port": 8443,
                    "protocol": "vless",
                    "settings": {"clients": [{"id": "plain-id"}], "decryption": "none"},
                    "streamSettings": {"network": "tcp", "security": "none"},
                },
                {
                    "tag": "reality",
                    "port": 443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": "real-id", "flow": "xtls-rprx-vision"}],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "www.microsoft.com:443",
                            "serverNames": ["www.microsoft.com"],
                            "privateKey": "priv",
                            "shortIds": ["aabb"],
                            "fingerprint": "firefox",
                        },
                    },
                },
            ],
            "outbounds": [{"protocol": "freedom"}],
        }

    def test_reads_reality_inbound_not_the_first_one(self):
        values = xray_form_values(self.config)
        self.assertEqual(values["port"], "443")
        self.assertEqual(values["sni"], "www.microsoft.com")
        self.assertEqual(values["fingerprint"], "firefox")
        self.assertEqual(values["transport"], "raw")

    def test_sni_change_keeps_decoy_clients_and_key(self):
        fields = dict(xray_form_values(self.config))
        fields.update({
            "sni": "www.example.com",
            "site": "www.example.com",
            "fingerprint": "chrome",
            "_private_key": "should-not-override",
            "_short_id": "should-not-override",
        })
        updated, errors = apply_xray_settings(self.config, fields)
        self.assertEqual(errors, [])
        decoy, reality = updated["inbounds"]
        self.assertEqual(decoy["port"], 8443)
        self.assertEqual(decoy["settings"]["clients"][0]["id"], "plain-id")
        reality_settings = reality["streamSettings"]["realitySettings"]
        self.assertEqual(reality_settings["privateKey"], "priv")
        self.assertEqual(reality_settings["shortIds"], ["aabb"])
        self.assertEqual(reality_settings["serverNames"], ["www.example.com"])
        self.assertEqual(reality["settings"]["clients"][0]["flow"], "xtls-rprx-vision")

    def test_xhttp_strips_vision_flow(self):
        fields = dict(xray_form_values(self.config))
        fields.update({
            "transport": "xhttp",
            "security": "reality",
            "xhttp_mode": "Stream-up",
            "xhttp_host": "www.example.com",
            "xhttp_path": "/cdn",
        })
        updated, errors = apply_xray_settings(self.config, fields)
        self.assertEqual(errors, [])
        reality = updated["inbounds"][1]
        stream = reality["streamSettings"]
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["xhttpSettings"]["mode"], "stream-up")
        self.assertEqual(stream["xhttpSettings"]["path"], "/cdn")
        self.assertNotIn("flow", reality["settings"]["clients"][0])

    def test_mkcp_cannot_keep_reality(self):
        fields = dict(xray_form_values(self.config))
        fields.update({"transport": "mkcp", "security": "reality"})
        updated, errors = apply_xray_settings(self.config, fields)
        self.assertEqual(errors, [])
        stream = updated["inbounds"][1]["streamSettings"]
        self.assertEqual(stream["network"], "kcp")
        self.assertEqual(stream["security"], "none")
        self.assertNotIn("realitySettings", stream)
        self.assertNotIn("flow", updated["inbounds"][1]["settings"]["clients"][0])

    def test_default_server_is_reality(self):
        config = default_xray_server(443, "priv", "abcd", "uuid-1")
        raw = json.dumps(config)
        self.assertIn("xtls-rprx-vision", raw)
        self.assertEqual(config["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], "priv")


class IpsecAndInstallTest(unittest.TestCase):
    def test_dns_replacement(self):
        text = "modecfgdns=1.1.1.1,1.0.0.1\nms-dns 1.1.1.1\nms-dns 1.0.0.1\n"
        updated = apply_ipsec_dns(text, "8.8.8.8", "8.8.4.4")
        self.assertIn("modecfgdns=8.8.8.8,8.8.4.4", updated)
        self.assertEqual(updated.count("8.8.8.8"), 2)
        self.assertIn("ms-dns 8.8.4.4", updated)

    def test_install_variables_cover_new_protocols(self):
        manager = ContainerManager(type("SSH", (), {"host": "203.0.113.10", "docker": "docker"})())
        xray = manager._install_variables("xray", "amnezia-xray", 443, "udp")
        self.assertEqual(xray["$XRAY_SERVER_PORT"], "443")
        self.assertEqual(xray["$XRAY_SITE_NAME"], "www.googletagmanager.com")
        ovpn = manager._install_variables("openvpn", "amnezia-openvpn", 1194, "tcp")
        self.assertEqual(ovpn["$OPENVPN_TRANSPORT_PROTO"], "tcp")
        self.assertEqual(ovpn["$OPENVPN_CIPHER"], "AES-256-GCM")
        self.assertIn("tls-auth", ovpn["$OPENVPN_TLS_AUTH"])
        ipsec = manager._install_variables("ipsec", "amnezia-ipsec", 500, "udp")
        self.assertEqual(ipsec["$IPSEC_VPN_DISABLE_IKEV2"], "no")
        self.assertEqual(ipsec["$SERVER_IP_ADDRESS"], "203.0.113.10")

    def test_forms_expose_editor_sections(self):
        awg = settings_form("awg", {"subnet": "10.8.1.0/24", "port": "55424", "mtu": "1376"})
        self.assertIn("HeaderProtectionKey", {item["name"] for section in awg["sections"] for item in section["fields"]})
        xray = settings_form("xray", {"port": "443", "transport": "raw", "security": "reality"})
        names = {item["name"] for section in xray["sections"] for item in section["fields"]}
        self.assertIn("flow", names)
        self.assertIn("xhttp_path", names)


if __name__ == "__main__":
    unittest.main()
