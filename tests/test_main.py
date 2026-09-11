"""Offline tests; no actual VPN, kernel modification, or network service required."""
import base64
import contextlib
import importlib.util
import io
import ipaddress
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "l2tp_ipsec_client" / "main.py"
spec = importlib.util.spec_from_file_location("addon", MODULE_PATH)
addon = importlib.util.module_from_spec(spec)
sys.modules["addon"] = addon
spec.loader.exec_module(addon)


def sample(**changes):
    data = {"vpn_server": "203.0.113.20", "vpn_username": "test-user",
            "vpn_password": 'pass with "quotes" \\ and $dollar #hash',
            "vpn_psk": 'psk with "quotes" \\ and ü', "adapter_ip": "192.168.50.60"}
    data.update(changes)
    return data


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = addon.Config.load(sample())
        self.assertEqual(cfg.port, 9999)
        self.assertEqual(cfg.auth, "mschapv2")
        self.assertFalse(cfg.legacy)
        self.assertEqual(cfg.max_retries, 3)

    def test_required_credentials(self):
        for key in ("vpn_server", "vpn_username", "vpn_password", "vpn_psk", "adapter_ip"):
            with self.subTest(key=key), self.assertRaises(addon.ConfigError):
                addon.Config.load(sample(**{key: ""}))

    def test_reject_control_character_injection(self):
        for key in ("vpn_server", "vpn_username", "vpn_password", "vpn_psk", "adapter_ip"):
            for control in ("\n", "\r", "\x00", "\x1b", "\t", "\x7f"):
                with self.subTest(key=key, control=repr(control)), self.assertRaises(addon.ConfigError):
                    addon.Config.load(sample(**{key: "abc" + control + "malicious"}))

    def test_reject_url_ipv6_or_cidr(self):
        for addr in ("https://203.0.113.20", "::1", "vpn.example.test", "192.168.1.0/24", "foo;bar"):
            with self.subTest(addr=addr), self.assertRaises(addon.ConfigError):
                addon.Config.load(sample(vpn_server=addr))

    def test_reject_non_unicast(self):
        for addr in ("0.0.0.0", "127.0.0.1", "224.1.1.1", "255.255.255.255"):
            with self.subTest(addr=addr), self.assertRaises(addon.ConfigError):
                addon.Config.load(sample(adapter_ip=addr))

    def test_same_server_adapter_rejected(self):
        with self.assertRaises(addon.ConfigError):
            addon.Config.load(sample(adapter_ip="203.0.113.20"))

    def test_invalid_ports(self):
        for port in (0, -1, 65536, "9999", True, None):
            with self.subTest(port=port), self.assertRaises(addon.ConfigError):
                addon.Config.load(sample(adapter_port=port))

    def test_authentication_modes(self):
        for mode in ("mschapv2", "chap", "pap", "auto"):
            with self.subTest(mode=mode):
                self.assertEqual(addon.Config.load(sample(ppp_auth=mode)).auth, mode)
        with self.assertRaises(addon.ConfigError):
            addon.Config.load(sample(ppp_auth="invalid"))

    def test_boolean_not_text(self):
        with self.assertRaises(addon.ConfigError):
            addon.Config.load(sample(legacy_compatibility="false"))

    def test_numeric_limits(self):
        for field, value in (("mtu", 9000), ("retry_delay", 0), ("max_retries", 999)):
            with self.subTest(field=field), self.assertRaises(addon.ConfigError):
                addon.Config.load(sample(**{field: value}))

    def test_acl_invalid(self):
        for nets in ([], ["::/0"], ["0.0.0.0/0"], ["bad"], "172.30.32.0/23"):
            with self.subTest(nets=nets), self.assertRaises(addon.ConfigError):
                addon.Config.load(sample(allowed_clients=nets))

    def test_acl_cidr_and_single_ip(self):
        cfg = addon.Config.load(sample(allowed_clients=["172.30.32.0/23", "192.168.1.9"]))
        self.assertTrue(addon.peer_allowed("172.30.33.15", cfg.allowed))
        self.assertTrue(addon.peer_allowed("192.168.1.9", cfg.allowed))
        self.assertFalse(addon.peer_allowed("192.168.1.10", cfg.allowed))
        self.assertFalse(addon.peer_allowed("not-an-ip", cfg.allowed))

    def test_config_repr_does_not_leak_credentials(self):
        cfg = addon.Config.load(sample())
        self.assertNotIn(cfg.password, repr(cfg))
        self.assertNotIn(cfg.psk, repr(cfg))


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.cfg = addon.Config.load(sample())
        self.files = addon.configurations(self.cfg)

    def test_ppp_quoting(self):
        self.assertEqual(addon.ppp_quote('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(addon.ppp_quote("white space # dollar$"), '"white space # dollar$"')

    def test_psk_roundtrip(self):
        encoded = self.files["ipsec.secrets"].strip().split("0s", 1)[1]
        self.assertEqual(base64.b64decode(encoded).decode(), self.cfg.psk)
        self.assertNotIn(self.cfg.psk, self.files["ipsec.secrets"])

    def test_ppp_credentials_in_private_file_only(self):
        self.assertIn("user " + addon.ppp_quote(self.cfg.username), self.files["ppp-options"])
        self.assertIn("password " + addon.ppp_quote(self.cfg.password), self.files["ppp-options"])
        self.assertNotIn(self.cfg.password, self.files["xl2tpd.conf"])
        self.assertNotIn(self.cfg.psk, self.files["ipsec.conf"])

    def test_no_default_route_or_peer_dns(self):
        lines = self.files["ppp-options"].splitlines()
        self.assertIn("nodefaultroute", lines)
        self.assertNotIn("defaultroute", lines)
        self.assertNotIn("replacedefaultroute", lines)
        self.assertNotIn("usepeerdns", lines)
        self.assertIn("install_routes = no", addon.strongswan_configuration())

    def test_no_legacy_crypto_without_opt_in(self):
        self.assertNotIn("modp1024", self.files["ipsec.conf"])
        self.assertNotIn("3des", self.files["ipsec.conf"])
        legacy = addon.configurations(addon.Config.load(sample(legacy_compatibility=True)))
        self.assertIn("modp1024", legacy["ipsec.conf"])
        self.assertIn("3des", legacy["ipsec.conf"])

    def test_transport_and_nat_t(self):
        self.assertIn("type=transport", self.files["ipsec.conf"])
        self.assertIn("forceencaps=yes", self.files["ipsec.conf"])
        self.assertIn("rightprotoport=17/1701", self.files["ipsec.conf"])

    def test_only_mschapv2_default(self):
        lines = self.files["ppp-options"].splitlines()
        for option in ("refuse-pap", "refuse-chap", "refuse-mschap", "refuse-eap"):
            self.assertIn(option, lines)
        self.assertNotIn("refuse-mschap-v2", lines)
        self.assertNotIn("require-mschap-v2", lines)

    def test_individual_auth_refusals(self):
        expected = {
            "chap": ["refuse-pap", "refuse-mschap", "refuse-mschap-v2"],
            "pap": ["refuse-chap", "refuse-mschap", "refuse-mschap-v2"],
        }
        for mode, options in expected.items():
            rendered = addon.configurations(addon.Config.load(sample(ppp_auth=mode)))["ppp-options"]
            for option in options:
                self.assertIn(option, rendered.splitlines())

    def test_sa_detection_requires_child_sa(self):
        self.assertTrue(addon.child_sa_installed("c6vpn{1}:  INSTALLED, TRANSPORT, reqid 1, ESP in UDP SPIs"))
        self.assertFalse(addon.child_sa_installed("c6vpn[1]: ESTABLISHED 2 seconds ago"))
        self.assertFalse(addon.child_sa_installed("other{1}: INSTALLED, TRANSPORT"))
        self.assertFalse(addon.child_sa_installed("c6vpn{1}: INSTALLED, TUNNEL"))

    def test_killswitches(self):
        rules = addon.firewall_commands(self.cfg)
        self.assertEqual(len(rules), 3)
        self.assertIn("none", rules[0])
        self.assertIn("REJECT", rules[0])
        self.assertIn("DROP", rules[1])
        self.assertIn(self.cfg.adapter, rules[2])
        self.assertIn(addon.PPP_INTERFACE, rules[2])
        self.assertIn("!", rules[2])

    def test_secret_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secrets"
            addon.secure_write(path, "fake secret")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            path.chmod(0o644)
            addon.secure_write(path, "updated fake secret")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_symlink_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_text("unchanged")
            link = Path(tmp) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                addon.secure_write(link, "modified")
            self.assertEqual(target.read_text(), "unchanged")

    def test_log_redaction(self):
        logger = addon.Logger(self.cfg)
        encoded = base64.b64encode(self.cfg.psk.encode()).decode()
        message = logger.redact(f"{self.cfg.username} {self.cfg.password} {self.cfg.psk} {encoded}")
        for value in (self.cfg.username, self.cfg.password, self.cfg.psk, encoded):
            self.assertNotIn(value, message)

    def test_authentication_failure_recognised(self):
        logger = addon.Logger(self.cfg)
        with contextlib.redirect_stdout(io.StringIO()):
            logger.daemon_line("pppd", "MS-CHAP authentication failed")
        self.assertTrue(logger.auth_failure.is_set())


class RelayTests(unittest.TestCase):
    def test_binary_bidirectional_relay(self):
        proxy = object.__new__(addon.Proxy)
        proxy.stop_event = threading.Event()
        left, left_inner = socket.socketpair()
        right_inner, right = socket.socketpair()
        for sock in (left, left_inner, right_inner, right):
            sock.settimeout(2)
        worker = threading.Thread(target=proxy.transfer, args=(left_inner, right_inner), daemon=True)
        worker.start()
        try:
            payload = bytes(range(256)) * 8
            left.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                received.extend(right.recv(8192))
            self.assertEqual(bytes(received), payload)
            right.sendall(b"\xaa\x00\xff\nreturn")
            self.assertEqual(left.recv(100), b"\xaa\x00\xff\nreturn")
            left.shutdown(socket.SHUT_WR)
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        finally:
            proxy.stop_event.set()
            for sock in (left, left_inner, right_inner, right):
                sock.close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
