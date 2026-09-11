"""Offline tests. Mocked TUN/VPN tests are NOT a real VPN compatibility test."""
import base64
import contextlib
import copy
import errno
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("c6_gateway", ROOT / "l2tp_ipsec_client/main.py")
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def data(**changes):
    d = dict(vpn_server="203.0.113.15", vpn_username="sample-user",
             vpn_password="not-a-real-password", vpn_psk="not-a-real-psk",
             adapter_ip="192.168.50.60", allowed_clients=["127.0.0.1/32"],
             ppp_auth="mschapv2", legacy_compatibility=False)
    d.update(changes)
    return d


class Base(unittest.TestCase):
    def setUp(self):
        m.STOP.clear()

    def tearDown(self):
        m.STOP.clear()


class ConfigTests(Base):
    def test_default_values(self):
        c = m.Config.load(data())
        self.assertEqual((c.port, c.mtu, c.max_retries), (9999, 1400, 3))

    def test_preserves_password_spaces(self):
        self.assertEqual(m.Config.load(data(vpn_password=" pass word ")).password, " pass word ")

    def test_missing_credentials(self):
        for key in ("vpn_server", "vpn_username", "vpn_password", "vpn_psk", "adapter_ip"):
            with self.subTest(key=key), self.assertRaises(m.ConfigError):
                m.Config.load(data(**{key: ""}))

    def test_rejects_ipv6_names_urls_and_controls(self):
        for value in ("::1", "example.com", "https://203.0.113.15", "203.0.113.15\n"):
            with self.subTest(value=value), self.assertRaises(m.ConfigError):
                m.Config.load(data(vpn_server=value))

    def test_rejects_non_unicast(self):
        for ip in ("0.0.0.0", "127.0.0.1", "224.1.1.1", "255.255.255.255"):
            with self.subTest(ip=ip), self.assertRaises(m.ConfigError):
                m.Config.load(data(adapter_ip=ip))

    def test_same_server_and_adapter(self):
        with self.assertRaises(m.ConfigError):
            m.Config.load(data(adapter_ip="203.0.113.15"))

    def test_unsupported_auth_modes(self):
        for auth in ("pap", "chap", "auto"):
            with self.subTest(auth=auth), self.assertRaises(m.ConfigError):
                m.Config.load(data(ppp_auth=auth))

    def test_no_silent_legacy_option(self):
        with self.assertRaises(m.ConfigError):
            m.Config.load(data(legacy_compatibility=True))

    def test_invalid_numeric_values(self):
        for key, value in (("adapter_port", 0), ("adapter_port", True), ("mtu", 500),
                           ("max_retries", 0), ("max_retries", 100), ("retry_delay", 1)):
            with self.subTest(key=key, value=value), self.assertRaises(m.ConfigError):
                m.Config.load(data(**{key: value}))

    def test_no_worldwide_or_empty_allowlist(self):
        for value in ([], ["0.0.0.0/0"], ["::/0"], "127.0.0.1", ["bad"]):
            with self.subTest(value=value), self.assertRaises(m.ConfigError):
                m.Config.load(data(allowed_clients=value))

    def test_boolean_strictness(self):
        with self.assertRaises(m.ConfigError):
            m.boolean({"x": "false"}, "x", True)

    def test_no_secret_in_config_repr(self):
        c = m.Config.load(data())
        for secret in (c.username, c.password, c.psk):
            self.assertNotIn(secret, repr(c))

    def test_rejects_oversized_and_control_credentials(self):
        for value in ("x" * 1025, "x\ny", "x\x1by"):
            with self.subTest(length=len(value)), self.assertRaises(m.ConfigError):
                m.Config.load(data(vpn_password=value))

    def test_credentials_only_required_fields(self):
        self.assertEqual(set(m.Config.load(data()).credentials()), {"server", "username", "password", "psk"})


class LoggingTests(Base):
    def test_redacts_plain_encoded_secrets(self):
        c = m.Config.load(data(vpn_password='sëcret"\\word'))
        logger = m.Logger(c)
        for value in (c.username, c.password, c.psk):
            variants = [value, json.dumps(value)[1:-1], base64.b64encode(value.encode()).decode(), value.encode().hex()]
            for variant in variants:
                with self.subTest(variant=variant):
                    self.assertNotIn(variant, logger.redact("error " + variant + " end"))

    def test_removes_terminal_controls(self):
        self.assertEqual(m.Logger().redact("a\n\r\x1bb"), "a   b")

    def test_printed_log_redacted(self):
        c = m.Config.load(data())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            m.Logger(c).log(c.password, "ERROR")
        self.assertNotIn(c.password, out.getvalue())
        self.assertIn("REDACTED", out.getvalue())


class RouteTests(Base):
    def test_only_adapter_host_route(self):
        c = m.Config.load(data())
        commands = m.route_commands(c, "10.10.1.8", 1400)
        self.assertIn(c.adapter + "/32", commands[-1])
        self.assertIn(m.TUN_INTERFACE, commands[-1])
        self.assertIn("10.10.1.8", commands[-1])
        for command in commands:
            self.assertNotIn("default", command)
            self.assertNotIn("0.0.0.0/0", command)
            self.assertNotIn("resolv.conf", " ".join(command))

    def test_dead_tunnel_blackhole(self):
        c = m.Config.load(data())
        command = m.blackhole_command(c)
        self.assertIn("blackhole", command)
        self.assertIn(c.adapter + "/32", command)
        self.assertEqual(command[-1], "42760")

    def test_mtu_capped(self):
        c = m.Config.load(data())
        self.assertIn("1350", m.route_commands(c, "10.1.1.2", 1350)[1])
        self.assertIn("1400", m.route_commands(c, "10.1.1.2", 99999)[1])

    def test_assigned_ip_collision(self):
        c = m.Config.load(data())
        for ip in (c.adapter, c.server):
            with self.subTest(ip=ip), self.assertRaises(RuntimeError):
                m.route_commands(c, ip, 1400)

    def test_adapter_docker_subnet_collision(self):
        c = m.Config.load(data(adapter_ip="172.30.33.25"))
        interfaces = [{"ifname": "eth0", "addr_info": [dict(family="inet", local="172.30.33.2", prefixlen=23)]}]
        with self.assertRaises(m.ConfigError):
            m.check_subnet_conflict(c, interfaces)

    def test_remote_subnet_does_not_collide(self):
        interfaces = [{"ifname": "eth0", "addr_info": [dict(family="inet", local="172.30.33.2", prefixlen=23)]}]
        m.check_subnet_conflict(m.Config.load(data()), interfaces)


class PreflightTests(Base):
    def test_missing_tun_reports_tun_not_ppp(self):
        runner = m.Runner(m.Logger())
        with mock.patch.object(m.os, "open", side_effect=FileNotFoundError(errno.ENOENT, "missing")):
            with self.assertRaisesRegex(RuntimeError, "/dev/net/tun"):
                m.tun_preflight(runner)

    def test_permission_error_has_errno(self):
        with mock.patch.object(m.os, "open", side_effect=PermissionError(errno.EPERM, "denied")):
            with self.assertRaisesRegex(RuntimeError, "errno=1"):
                m.tun_preflight(m.Runner(m.Logger()))

    def test_mocked_success_closes_tun_and_starts_only_version(self):
        runner = mock.Mock()
        runner.command.return_value = subprocess.CompletedProcess([], 0, "c6-vpn-engine 0.2.0; test", "")
        interface = struct.pack("16sH22x", b"c6diag0", 0)
        with mock.patch.object(m.os, "open", return_value=95), \
             mock.patch.object(m.os, "fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFCHR)), \
             mock.patch.object(m.fcntl, "ioctl", return_value=interface) as ioctl, \
             mock.patch.object(m.os, "close") as close, \
             mock.patch.object(m.socket, "socket"):
            m.tun_preflight(runner)
        close.assert_called_once_with(95)
        self.assertEqual(ioctl.call_args.args[1], 0x400454CA)
        runner.command.assert_called_once_with([m.ENGINE, "--version"])

    def test_wrong_engine_version_fails(self):
        runner = mock.Mock()
        runner.command.return_value = subprocess.CompletedProcess([], 0, "old-engine", "")
        with mock.patch.object(m.os, "open", return_value=95), \
             mock.patch.object(m.os, "fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFCHR)), \
             mock.patch.object(m.fcntl, "ioctl", return_value=struct.pack("16sH22x", b"test", 0)), \
             mock.patch.object(m.os, "close"), mock.patch.object(m.socket, "socket"):
            with self.assertRaisesRegex(RuntimeError, "0.2.0"):
                m.tun_preflight(runner)

    def test_diagnostic_needs_no_password_and_never_connects(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "options.json"
            p.write_text('{"diagnostics_only":true}')
            with mock.patch.object(m, "tun_preflight") as preflight, \
                 mock.patch.object(m, "VPNProcess") as vpn, \
                 mock.patch.object(m.signal, "signal"):
                self.assertEqual(m.main(p, check_only=True), 0)
            preflight.assert_called_once()
            vpn.assert_not_called()


class EngineEventTests(Base):
    def make_engine(self):
        e = m.VPNProcess.__new__(m.VPNProcess)
        e.logger = m.Logger(m.Config.load(data()))
        e.ready = threading.Event()
        e.up, e.error, e.auth = None, None, False
        e.process = mock.Mock()
        e.process.poll.return_value = None
        return e

    def test_up_event(self):
        e = self.make_engine()
        e.handle_event(json.dumps(dict(event="vpn_up", interface=m.TUN_INTERFACE, address="10.1.1.2", mtu=1400)))
        self.assertEqual(e.up, {"address": "10.1.1.2", "mtu": 1400})
        self.assertTrue(e.ready.is_set())
        e.check()

    def test_auth_error_stops_retry(self):
        e = self.make_engine()
        e.handle_event('{"event":"error","auth":true,"message":"auth failed"}')
        with self.assertRaises(m.AuthenticationError):
            e.check()

    def test_invalid_events_fail_closed(self):
        for text in ('[]', 'bad-json', '{"event":"unknown"}',
                     '{"event":"vpn_up","interface":"eth0","address":"10.1.1.2"}',
                     '{"event":"vpn_up","interface":"c6vpn0","address":"bad"}'):
            with self.subTest(text=text):
                e = self.make_engine()
                e.handle_event(text)
                with self.assertRaises(RuntimeError):
                    e.check()

    def test_warning_is_not_readiness(self):
        e = self.make_engine()
        e.handle_event('{"event":"warning","message":"test"}')
        self.assertIsNone(e.up)
        self.assertFalse(e.ready.is_set())


class SocketTests(Base):
    def test_socket_bound_before_connect(self):
        fake = mock.Mock()
        with mock.patch.object(m.socket, "socket", return_value=fake):
            self.assertIs(m.vpn_socket(m.Config.load(data()), "10.1.1.2"), fake)
        calls = fake.mock_calls
        binddev = mock.call.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"c6vpn0\0")
        self.assertLess(calls.index(binddev), calls.index(mock.call.connect(("192.168.50.60", 9999))))
        self.assertLess(calls.index(mock.call.bind(("10.1.1.2", 0))), calls.index(mock.call.connect(("192.168.50.60", 9999))))

    def test_bind_failure_never_connects(self):
        fake = mock.Mock()
        def opt(level, name, value):
            if name == socket.SO_BINDTODEVICE:
                raise OSError(errno.EPERM, "denied")
        fake.setsockopt.side_effect = opt
        with mock.patch.object(m.socket, "socket", return_value=fake):
            with self.assertRaises(OSError):
                m.vpn_socket(m.Config.load(data()), "10.1.1.2")
        fake.connect.assert_not_called()
        fake.close.assert_called_once()

    def test_allowlist(self):
        nets = (ipaddress.IPv4Network("172.30.32.0/23"),)
        self.assertTrue(m.peer_allowed("172.30.33.4", nets))
        for value in ("192.168.1.20", "::1", "garbage"):
            self.assertFalse(m.peer_allowed(value, nets))


class RelayIntegrationTests(Base):
    """Real loopback TCP/socketpair relay tests, NOT an IPsec/VPN server."""
    def setUp(self):
        super().setUp()
        self.peers = []
        self.connected = threading.Event()
        self.proxy = None

    def tearDown(self):
        if self.proxy:
            self.proxy.close()
        for s in self.peers:
            s.close()
        super().tearDown()

    def dialer(self, cfg, address):
        a, b = socket.socketpair()
        a.settimeout(2)
        b.settimeout(2)
        self.peers.append(b)
        self.connected.set()
        return a

    def start(self, allowed=None):
        cfg = m.Config.load(data(allowed_clients=allowed or ["127.0.0.1/32"]))
        self.proxy = m.Proxy(cfg, "10.1.1.2", m.Logger(cfg), listen_port=0,
                            listen_host="127.0.0.1", dialer=self.dialer)
        return socket.create_connection(("127.0.0.1", self.proxy.port), timeout=2)

    def test_binary_data_both_directions(self):
        with self.start() as client:
            self.assertTrue(self.connected.wait(2))
            payload = bytes(range(256)) * 2
            client.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                received.extend(self.peers[0].recv(1024))
            self.assertEqual(received, payload)
            self.peers[0].sendall(b"\x00\xffreply\xaa")
            self.assertEqual(client.recv(1024), b"\x00\xffreply\xaa")

    def test_unlisted_client_never_dials(self):
        with self.start(["192.168.2.5/32"]) as client:
            self.assertEqual(client.recv(1), b"")
            self.assertFalse(self.connected.is_set())

    def test_second_client_rejected(self):
        with self.start() as first:
            self.assertTrue(self.connected.wait(2))
            with socket.create_connection(("127.0.0.1", self.proxy.port), timeout=2) as second:
                self.assertEqual(second.recv(1), b"")
            self.assertEqual(len(self.peers), 1)

    def test_shutdown_closes_existing_link(self):
        with self.start() as client:
            self.assertTrue(self.connected.wait(2))
            self.proxy.close()
            self.assertEqual(client.recv(1), b"")
            self.assertFalse(self.proxy.thread.is_alive())


class PackagingTests(Base):
    def test_manifest_is_constrained(self):
        import yaml
        cfg = yaml.safe_load((ROOT / "l2tp_ipsec_client/config.yaml").read_text())
        self.assertEqual(cfg["version"], "0.2.0")
        self.assertEqual(cfg["slug"], "l2tp_ipsec_client")
        for key in ("host_network", "full_access", "kernel_modules"):
            self.assertFalse(cfg[key])
        self.assertTrue(cfg["apparmor"])
        self.assertEqual(set(cfg["privileged"]), {"NET_ADMIN", "NET_RAW"})
        self.assertEqual(cfg["devices"], ["/dev/net/tun"])
        self.assertIsNone(cfg["ports"]["9999/tcp"])
        self.assertTrue(cfg["options"]["diagnostics_only"])
        self.assertEqual(set(cfg["arch"]), {"amd64", "aarch64"})

    def test_engine_dependency_fixed(self):
        docker = (ROOT / "l2tp_ipsec_client/Dockerfile").read_text()
        self.assertIn("6c37e3691c326e54956cea042e2df67d3717e7a4", docker)
        self.assertNotIn("--privileged", docker)
        self.assertIn("go test ./cmd/ha-c6vpn", docker)

    def test_no_kernel_ppp_or_default_route_commands(self):
        text = (ROOT / "l2tp_ipsec_client/main.py").read_text()
        for forbidden in ('"modprobe"', '"pppd"', '"xl2tpd"', '"defaultroute"', '"ipsec"'):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
