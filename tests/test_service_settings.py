"""Службы Amnezia: разбор конфигов, ссылки и переменные установки."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from container_manager import ContainerManager, publish_flags
from service_settings import (
    domain_hex,
    mtproxy_env,
    mtproxy_values,
    parse_sftp_cmd,
    parse_socks,
    proxy_client_secret,
    service_form,
    socks_env,
    telegram_links,
    telemt_env,
    telemt_values,
    tproxy_env,
    tproxy_values,
    validate_login,
    validate_proxy_fields,
    validate_tproxy,
    webproxy_links,
)


SECRET = "0123456789abcdef0123456789abcdef"
TOML = """
[general]
use_middle_proxy = true
ad_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
middle_proxy_nat_ip = "203.0.113.10"

[general.modes]
classic = false
secure = false
tls = true

[general.links]
show = "*"
public_host = "proxy.example.com"
public_port = 8443

[censorship]
tls_domain = "example.com"
mask = false
tls_emulation = true

[access.users]
amnezia = "0123456789abcdef0123456789abcdef"
extra_1 = "abcdefabcdefabcdefabcdefabcdefab"
"""


def manager():
    ssh = type("SSH", (), {"host": "203.0.113.10", "docker": "docker"})()
    return ContainerManager(ssh)


class LinkAndParseTest(unittest.TestCase):
    def test_faketls_secret_and_links(self):
        client = proxy_client_secret(SECRET, "faketls", "example.com")
        self.assertTrue(client.startswith("ee" + SECRET))
        self.assertTrue(client.endswith(domain_hex("example.com")))
        tg, tme = telegram_links("203.0.113.10", "443", client)
        self.assertIn("tg://proxy?server=203.0.113.10&port=443&secret=ee", tg)
        self.assertTrue(tme.startswith("https://t.me/proxy?"))

    def test_standard_secret_is_dd(self):
        self.assertEqual(proxy_client_secret(SECRET, "standard", "example.com"), "dd" + SECRET)

    def test_webproxy_uses_raw_secret(self):
        tg, tme = webproxy_links("proxy.example.com", SECRET)
        self.assertEqual(tg, f"tg://webproxy?server=proxy.example.com&secret={SECRET}")
        self.assertIn("https://t.me/webproxy?", tme)

    def test_mtproxy_meta_roundtrip(self):
        meta = "\n".join([
            "mode=faketls",
            "domain=example.com",
            "tag=" + SECRET,
            "additional=" + SECRET,
            "workers_mode=manual",
            "workers=0",
            "nat_enabled=1",
            "nat_internal=10.0.0.2",
            "nat_external=203.0.113.10",
            "public_host=proxy.example.com",
        ])
        values = mtproxy_values(meta, SECRET + "\n", "198.51.100.1")
        self.assertEqual(values["transport_mode"], "faketls")
        self.assertEqual(values["workers"], "0")
        self.assertTrue(values["nat_enabled"])
        self.assertIn("proxy.example.com", values["tg_link"])
        self.assertNotIn("198.51.100.1", values["tg_link"])

    def test_telemt_ignores_ad_tag_as_user(self):
        values = telemt_values(TOML, SECRET, "198.51.100.1")
        self.assertEqual(values["user_name"], "amnezia")
        self.assertEqual(values["transport_mode"], "faketls")
        self.assertEqual(values["port"], "8443")
        self.assertEqual(values["tag"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertIn("abcdefabcdefabcdefabcdefabcdefab", values["additional_secrets"])
        self.assertNotIn("ad_tag", values["user_name"])
        self.assertFalse(values["mask"])
        self.assertTrue(values["tls_emulation"])
        self.assertEqual(values["nat_external"], "203.0.113.10")
        self.assertIn("ee", values["tg_link"])

    def test_tproxy_meta(self):
        meta = "hostname=proxy.example.com\nemail=a@b.co\ncarrier=websocket\nworkers=4\nhttp_port=8080\nhttps_port=8443\n"
        values = tproxy_values(meta, SECRET)
        self.assertEqual(values["carrier_mode"], "websocket")
        self.assertEqual(values["tg_link"], f"tg://webproxy?server=proxy.example.com&secret={SECRET}")

    def test_socks_and_sftp_parsers(self):
        parsed = parse_socks('users proxy_user:CL:secretpass\nsocks -p38080\n')
        self.assertEqual(parsed, {"port": "38080", "username": "proxy_user", "password": "secretpass"})
        self.assertEqual(parse_sftp_cmd('["sftp_user:passWORD12:::upload"]'), ("sftp_user", "passWORD12"))
        self.assertEqual(parse_sftp_cmd("sleep 3600"), ("", ""))


class ValidationTest(unittest.TestCase):
    def test_faketls_auto_workers_are_zero(self):
        cleaned, errors = validate_proxy_fields({
            "port": "443",
            "transport_mode": "faketls",
            "tls_domain": "example.com",
            "workers_mode": "auto",
        }, "mtproxy")
        self.assertEqual(errors, [])
        self.assertEqual(cleaned["workers"], "0")
        env = mtproxy_env(cleaned, SECRET, regenerate=False)
        self.assertEqual(env["$MTPROXY_SECRET"], SECRET)
        self.assertEqual(env["$MTPROXY_REGENERATE_SECRET"], "0")
        fresh = mtproxy_env(cleaned, SECRET, regenerate=True)
        self.assertEqual(fresh["$MTPROXY_SECRET"], "")
        self.assertEqual(fresh["$MTPROXY_REGENERATE_SECRET"], "1")

    def test_manual_zero_workers(self):
        cleaned, errors = validate_proxy_fields({
            "port": "443",
            "transport_mode": "standard",
            "workers_mode": "manual",
            "workers": "0",
        }, "mtproxy")
        self.assertEqual(errors, [])
        self.assertEqual(cleaned["workers"], "0")

    def test_unchecked_telemt_flags_are_false(self):
        cleaned, errors = validate_proxy_fields({
            "port": "443",
            "transport_mode": "standard",
            "user_name": "amnezia",
        }, "telemt")
        self.assertEqual(errors, [])
        self.assertFalse(cleaned["mask"])
        self.assertFalse(cleaned["use_middle_proxy"])
        env = telemt_env(cleaned, SECRET, False)
        self.assertEqual(env["$TELEMT_TOML_SECURE"], "true")
        self.assertEqual(env["$TELEMT_TOML_TLS"], "false")
        self.assertEqual(env["$TELEMT_MASK"], "false")

    def test_bad_tag_and_login(self):
        _cleaned, errors = validate_proxy_fields({"port": "443", "tag": "zz"}, "telemt")
        self.assertTrue(errors)
        user, _password, login_errors = validate_login("bad:name", "short", False)
        self.assertTrue(login_errors)
        self.assertEqual(user, "bad:name")
        empty_user, empty_password, empty_errors = validate_login("", "", True)
        self.assertEqual((empty_user, empty_password, empty_errors), ("", "", []))

    def test_tproxy_requires_host_and_email(self):
        _cleaned, errors = validate_tproxy({"hostname": "-bad", "acme_email": "nope"})
        self.assertTrue(any("Hostname" in item for item in errors))
        self.assertTrue(any("email" in item for item in errors))
        cleaned, errors = validate_tproxy({
            "hostname": "Proxy.Example.com",
            "acme_email": "admin@example.com",
            "carrier_mode": "https-lanes",
            "workers": "2",
            "http_port": "80",
            "https_port": "443",
        })
        self.assertEqual(errors, [])
        self.assertEqual(cleaned["hostname"], "proxy.example.com")
        env = tproxy_env(cleaned, SECRET, False)
        self.assertEqual(env["$TPROXY_HOSTNAME"], "proxy.example.com")
        self.assertEqual(env["$TPROXY_CARRIER_MODE"], "https-lanes")

    def test_forms(self):
        dns = service_form("dns", {})
        self.assertTrue(dns["readonly"])
        tor = service_form("tor", {"hostname": "abc.onion"})
        self.assertTrue(tor["readonly"])
        self.assertEqual(tor["sections"][0]["fields"][0]["value"], "abc.onion")
        socks = service_form("socks5", {"port": "1080", "username": "", "password": ""})
        names = [item["name"] for item in socks["sections"][0]["fields"]]
        self.assertEqual(names, ["port", "username", "password"])


class InstallScriptTest(unittest.TestCase):
    def test_publish_flags(self):
        self.assertEqual(publish_flags([("443", "tcp")]), "-p 443:443/tcp")
        self.assertEqual(
            publish_flags([("222", "22", "tcp"), ("8080", "80", "tcp")]),
            "-p 222:22/tcp -p 8080:80/tcp",
        )

    def test_missing_script_is_empty(self):
        self.assertEqual(manager()._script_text("dns", "start.sh"), "")
        self.assertEqual(manager()._script_text("sftp", "start.sh"), "")
        self.assertEqual(manager()._script_text("website_tor", "start.sh"), "")

    def test_service_variables_cover_scripts(self):
        panel = manager()
        cases = {
            "sftp": ("sftp", ["$SFTP_PORT", "$SFTP_USER", "$SFTP_PASSWORD"], {"password": "sftpPass123"}),
            "socks5": ("socks5_proxy", ["$SOCKS5_PROXY_PORT", "$SOCKS5_USER", "$SOCKS5_AUTH_TYPE"],
                       {"username": "proxy_user", "password": "proxyPass123"}),
            "mtproxy": ("mtproxy", None, {"transport_mode": "faketls", "tls_domain": "example.com"}),
            "telemt": ("telemt", None, {"transport_mode": "standard", "public_host": "proxy.example.com"}),
            "tproxy": ("tproxy", None, {"hostname": "proxy.example.com", "acme_email": "admin@example.com"}),
            "dns": ("dns", [], {}),
            "tor": ("website_tor", [], {}),
        }
        for protocol, (directory, keys, fields) in cases.items():
            port = 443 if protocol in ("mtproxy", "telemt", "tproxy") else 222
            variables = panel._install_variables(protocol, f"amnezia-{protocol}", port, "tcp", fields)
            if protocol == "socks5":
                keys = list(socks_env("1", "a", "b"))
            if protocol == "mtproxy":
                keys = [key for key in variables if key.startswith("$MTPROXY_")]
                self.assertEqual(variables["$MTPROXY_REGENERATE_SECRET"], "1")
                self.assertEqual(variables["$MTPROXY_WORKERS"], "0")
            if protocol == "telemt":
                keys = [key for key in variables if key.startswith("$TELEMT_")]
                self.assertEqual(variables["$TELEMT_MASK"], "true")
                self.assertEqual(variables["$TELEMT_USE_MIDDLE_PROXY"], "true")
            if protocol == "tproxy":
                keys = [key for key in variables if key.startswith("$TPROXY_")]
                self.assertEqual(variables["$TPROXY_HTTP_PORT"], "80")
                self.assertEqual(variables["$TPROXY_HTTPS_PORT"], "443")
            if protocol == "sftp":
                self.assertEqual(variables["$SFTP_USER"], "sftp_user")
                self.assertEqual(variables["$SFTP_PORT"], "222")
            combined = "\n".join(
                panel._script_text(directory, name)
                for name in ("run_container.sh", "configure_container.sh", "start.sh")
            )
            rendered = panel._subst(combined, variables)
            for key in keys:
                self.assertNotIn(key, rendered, protocol)
            self.assertIsNone(re.search(r"\$(MTPROXY|TELEMT|TPROXY|SOCKS5|SFTP)_[A-Z0-9_]+", rendered), protocol)

    def test_clients_table_not_required_for_services(self):
        self.assertNotIn("ipsec", {"awg2", "wireguard", "openvpn", "xray"} & set())
        from container_manager import CLIENT_TABLE_PROTOCOLS
        self.assertEqual(CLIENT_TABLE_PROTOCOLS, {"awg2", "wireguard", "openvpn", "xray"})


if __name__ == "__main__":
    unittest.main()
