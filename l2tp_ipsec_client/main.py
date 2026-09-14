#!/usr/bin/env python3
"""Experimental HA C6 gateway: veepin userspace PPP + a VPN-bound TCP relay.

The host kernel needs TUN, not PPP/L2TP/XFRM. No shell interpolation, no
credential arguments, no default-route/DNS changes, no host networking.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from vpn_tools import IKETrace, discovery_networks, discovery_ports, scan_networks

VERSION = "0.2.1"
ENGINE_VERSION = "0.2.1"
ENGINE = "/usr/local/bin/c6-vpn-engine"
TUN_INTERFACE = "c6vpn0"
LISTEN_PORT = 9999
STOP = threading.Event()


class ConfigError(ValueError):
    pass


class AuthenticationError(RuntimeError):
    pass


def clean_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"Hiányzó vagy hibás szöveges beállítás: {field}.")
    if len(value.encode("utf-8")) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError(f"A(z) {field} mező túl hosszú vagy vezérlőkaraktert tartalmaz.")
    return value  # Leading/trailing spaces in credentials are significant.


def unicast_ipv4(value: Any, field: str) -> str:
    value = clean_text(value, field)
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ConfigError(f"A(z) {field} mezőbe IPv4-cím kell, nem URL vagy név.") from None
    if (addr.is_unspecified or addr.is_loopback or addr.is_multicast
            or addr.is_reserved or int(addr) == 0xffffffff):
        raise ConfigError(f"A(z) {field} mezőben nem használható ez a címfajta.")
    return str(addr)


def boolean(data: dict[str, Any], name: str, default: bool) -> bool:
    value = data.get(name, default)
    if type(value) is not bool:
        raise ConfigError(f"A(z) {name} true vagy false legyen.")
    return value


def number(data: dict[str, Any], name: str, default: int, low: int, high: int) -> int:
    value = data.get(name, default)
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"A(z) {name} egész szám legyen {low} és {high} között.")
    return value


@dataclass(frozen=True, repr=False)
class Config:
    server: str
    username: str
    password: str
    psk: str
    adapter: str
    port: int
    mtu: int
    retry_delay: int
    max_retries: int
    allowed: tuple[ipaddress.IPv4Network, ...]
    mode: str = "proxy"
    networks: tuple[ipaddress.IPv4Network, ...] = ()
    scan_ports: tuple[int, ...] = (9999, 80, 443)
    ike_trace: bool = False

    def target_networks(self) -> tuple[ipaddress.IPv4Network, ...]:
        if self.mode == "discover":
            return self.networks
        if self.mode == "proxy":
            return (ipaddress.IPv4Network(self.adapter + "/32"),)
        return ()

    @classmethod
    def load(cls, data: dict[str, Any]) -> "Config":
        server = unicast_ipv4(data.get("vpn_server"), "vpn_server")
        mode = data.get("connection_mode", "proxy")
        if mode not in ("proxy", "vpn_test", "discover"):
            raise ConfigError("A connection_mode proxy, vpn_test vagy discover legyen.")
        # In test/discovery mode the previous adapter value is deliberately ignored.
        adapter = unicast_ipv4(data.get("adapter_ip"), "adapter_ip") if mode == "proxy" else ""
        networks, ports = (), (9999, 80, 443)
        if mode == "discover":
            try:
                networks = discovery_networks(data.get("discovery_networks", []))
                ports = discovery_ports(data.get("discovery_ports", [9999, 80, 443]))
            except ValueError as err:
                raise ConfigError(str(err)) from None
            if any(ipaddress.IPv4Address(server) in n for n in networks):
                raise ConfigError("A VPN-szerver címe nem lehet a keresési tartományban.")
        if server == adapter:
            raise ConfigError("A VPN-szerver és az adapter címe nem lehet azonos.")
        if data.get("ppp_auth", "mschapv2") != "mschapv2":
            raise ConfigError("A 0.2.x csak ppp_auth: mschapv2 beállítást támogat. PAP/CHAP/auto nincs megvalósítva.")
        if boolean(data, "legacy_compatibility", False):
            raise ConfigError("A legacy_compatibility kapcsoló az új motorban nem támogatott; állítsd false-ra.")
        nets = data.get("allowed_clients", ["172.30.32.0/23", "127.0.0.1/32"])
        if not isinstance(nets, list) or not 1 <= len(nets) <= 64:
            raise ConfigError("Az allowed_clients 1–64 darab IPv4-cím vagy CIDR listája legyen.")
        allowed = []
        for value in nets:
            try:
                net = ipaddress.IPv4Network(clean_text(value, "allowed_clients"), strict=False)
            except ValueError:
                raise ConfigError("Hibás IPv4-cím vagy CIDR az allowed_clients listában.") from None
            if net.prefixlen == 0:
                raise ConfigError("A 0.0.0.0/0 engedélyezése tilos; konkrét klienscímet adj meg.")
            allowed.append(net)
        return cls(
            server, clean_text(data.get("vpn_username"), "vpn_username"),
            clean_text(data.get("vpn_password"), "vpn_password"),
            clean_text(data.get("vpn_psk"), "vpn_psk"), adapter,
            number(data, "adapter_port", 9999, 1, 65535),
            number(data, "mtu", 1400, 1280, 1460),
            number(data, "retry_delay", 60, 30, 600),
            number(data, "max_retries", 3, 1, 10), tuple(allowed),
            mode, networks, ports, boolean(data, "ike_trace", False),
        )

    def credentials(self) -> dict[str, str]:
        return {"server": self.server, "username": self.username,
                "password": self.password, "psk": self.psk}


class Logger:
    def __init__(self, cfg: Config | None = None):
        self.lock = threading.Lock()
        self.secrets: list[str] = []
        if cfg:
            for value in (cfg.username, cfg.password, cfg.psk):
                self.secrets.extend([
                    value, json.dumps(value, ensure_ascii=True)[1:-1],
                    json.dumps(value, ensure_ascii=False)[1:-1],
                    base64.b64encode(value.encode()).decode(), value.encode().hex(),
                ])
            self.secrets = sorted(set(self.secrets), key=len, reverse=True)

    def redact(self, message: str) -> str:
        for secret in self.secrets:
            if secret:
                message = message.replace(secret, "[REDACTED]")
        # Avoid terminal escapes or forged multi-line log records from a peer.
        return "".join(c if ord(c) >= 32 and ord(c) != 127 else " " for c in message)

    def log(self, message: str, level: str = "INFO") -> None:
        with self.lock:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{level}] {self.redact(message)}", flush=True)


class Runner:
    def __init__(self, logger: Logger):
        self.logger = logger

    def command(self, args: list[str], *, required: bool = True, timeout: int = 10) -> subprocess.CompletedProcess[str]:
        try:
            out = subprocess.run(args, capture_output=True, text=True, errors="replace",
                                 timeout=timeout, env={**os.environ, "LC_ALL": "C"}, check=False)
        except (OSError, subprocess.TimeoutExpired) as err:
            raise RuntimeError(f"A(z) {args[0]} parancs nem futtatható ({type(err).__name__}).") from None
        if required and out.returncode:
            self.logger.log((out.stderr or out.stdout).strip(), "ERROR")
            raise RuntimeError(f"A(z) {args[0]} parancs hibakódja: {out.returncode}.")
        return out


def tun_preflight(runner: Runner) -> None:
    """Create/destroy an unconfigured temporary TUN. No network packets sent."""
    log = runner.logger.log
    log(f"Kernel: {os.uname().release}; architektúra: {os.uname().machine}.")
    log("PPP_KERNEL_NOT_REQUIRED – a PPP/L2TP/IPsec protokollt a kliensprogram kezeli.")
    path = "/dev/net/tun"
    fd = None
    try:
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            raise RuntimeError("A /dev/net/tun nem karakteres eszköz.")
        # struct ifreq is 40 bytes on Linux amd64/aarch64; TUNSETIFF expects its prefix.
        req = struct.pack("16sH22x", b"c6diag%d", 0x0001 | 0x1000)  # IFF_TUN | IFF_NO_PI
        result = fcntl.ioctl(fd, 0x400454CA, req)
        interface = result[:16].split(b"\0", 1)[0]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface + b"\0")
    except OSError as err:
        if err.errno == errno.ENOENT:
            detail = "A /dev/net/tun nincs átadva az addonnak. Ellenőrizd, hogy valóban 0.2.x-re frissült-e."
        elif err.errno in (errno.EPERM, errno.EACCES):
            detail = "A TUN-próbát jogosultság/AppArmor/eszközengedély akadályozza. NET_ADMIN és TUN-hozzáférés szükséges."
        else:
            detail = "A TUN-eszközpróba sikertelen."
        raise RuntimeError(f"{detail} errno={err.errno}. Ez nem PPP-hiba.") from None
    finally:
        if fd is not None:
            os.close(fd)  # No persist flag: destroys the temporary TUN.
    log("TUN_OK – az ideiglenes TUN létrehozása és a socket interfészhez kötése sikeres.")
    out = runner.command([ENGINE, "--version"])
    if f"c6-vpn-engine {ENGINE_VERSION};" not in out.stdout:
        raise RuntimeError(f"Nem a {ENGINE_VERSION} VPN-motor található a konténerben.")
    log(out.stdout.strip())
    log("ENGINE_OK – a kliensprogram elindítható; VPN-bejelentkezés nem történt.")


def check_subnet_conflict(cfg: Config, interfaces: list[dict[str, Any]]) -> None:
    for iface in interfaces:
        if iface.get("ifname") in ("lo", TUN_INTERFACE):
            continue
        for item in iface.get("addr_info", []):
            if item.get("family") == "inet":
                net = ipaddress.IPv4Network(f"{item['local']}/{item['prefixlen']}", strict=False)
                if any(target.overlaps(net) for target in cfg.target_networks()):
                    raise ConfigError("A célhálózat ütközik az addon belső konténerhálózatával.")


def blackhole_command(cfg: Config) -> list[str]:
    # Less preferred than the live TUN's metric 5; remains when that TUN disappears.
    return ["ip", "-4", "route", "replace", "blackhole", cfg.adapter + "/32", "metric", "42760"]


def route_commands(cfg: Config, address: str, engine_mtu: int) -> list[list[str]]:
    address = unicast_ipv4(address, "kiosztott VPN-cím")
    if address in {cfg.server, cfg.adapter}:
        raise RuntimeError("A kiosztott VPN-cím ütközik a VPN-szerver vagy a C6 címével.")
    mtu = min(cfg.mtu, engine_mtu if 576 <= engine_mtu <= 9000 else cfg.mtu)
    commands = [
        ["ip", "-4", "address", "add", address + "/32", "dev", TUN_INTERFACE],
        ["ip", "link", "set", "dev", TUN_INTERFACE, "mtu", str(mtu), "up"],
    ]
    for target in cfg.target_networks():
        commands.append(["ip", "-4", "route", "replace", str(target), "dev", TUN_INTERFACE,
                         "src", address, "metric", "5"])
    return commands


def start_ike_trace(cfg: Config, runner: Runner) -> IKETrace | None:
    if not cfg.ike_trace:
        return None
    try:
        out = runner.command(["ip", "-j", "-4", "route", "get", cfg.server])
        route = json.loads(out.stdout)[0]
        interface = route["dev"]
        if interface == TUN_INTERFACE:
            raise RuntimeError("A VPN-szerver útvonala tévesen a VPN-re mutat.")
        runner.logger.log(f"VPN_OUTER_ROUTE dev={interface} src={route.get('prefsrc', '?')} via={route.get('gateway', '-')}")
        return IKETrace(cfg.server, interface, runner.logger.log)
    except (RuntimeError, OSError, ValueError, KeyError, IndexError) as err:
        runner.logger.log("IKE_TRACE_UNAVAILABLE – a metaadat-naplózás nem indult: " + str(err) +
                          ". A VPN-próba ettől még folytatódik.", "WARN")
        return None



class VPNProcess:
    def __init__(self, cfg: Config, logger: Logger):
        self.logger = logger
        self.ready = threading.Event()
        self.up: dict[str, Any] | None = None
        self.error: str | None = None
        self.auth = False
        self.process = subprocess.Popen(
            [ENGINE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", bufsize=1, start_new_session=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        self.threads = [
            threading.Thread(target=self.read_events, daemon=True, name="vpn-events"),
            threading.Thread(target=self.read_logs, daemon=True, name="vpn-logs"),
        ]
        for thread in self.threads:
            thread.start()
        try:
            assert self.process.stdin is not None
            json.dump(cfg.credentials(), self.process.stdin, ensure_ascii=False)
            self.process.stdin.write("\n")
            self.process.stdin.close()
        except Exception:
            self.close()
            raise

    def handle_event(self, text: str) -> None:
        try:
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError("not an object")
            name = value.get("event")
            if name == "vpn_up":
                if value.get("interface") != TUN_INTERFACE:
                    raise ValueError("unexpected interface")
                address = unicast_ipv4(value.get("address"), "VPN-cím")
                mtu = value.get("mtu", 1400)
                if type(mtu) is not int:
                    raise ValueError("invalid MTU")
                self.up = {"address": address, "mtu": mtu}
                self.ready.set()
            elif name == "error":
                self.error = str(value.get("message", "VPN-motor hiba"))
                self.auth = value.get("auth") is True
                self.ready.set()
            elif name == "warning":
                self.logger.log(str(value.get("message", "VPN-motor figyelmeztetés")), "WARN")
            elif name == "connecting":
                self.logger.log("VPN_CONNECTING – IKEv1/IPsec, majd L2TP és MS-CHAPv2 kapcsolatfelépítés.")
            else:
                raise ValueError("unknown engine event")
        except (ValueError, TypeError):
            self.error = "Hibás vagy nem várt válasz a VPN-motortól."
            self.ready.set()

    def read_events(self) -> None:
        assert self.process.stdout is not None
        try:
            for line in self.process.stdout:
                self.handle_event(line)
        finally:
            self.process.stdout.close()
            self.ready.set()

    def read_logs(self) -> None:
        assert self.process.stderr is not None
        try:
            for line in self.process.stderr:
                self.logger.log("VPN: " + line.rstrip())
        finally:
            self.process.stderr.close()

    def check(self) -> None:
        if self.error:
            if self.auth:
                raise AuthenticationError("Hitelesítési hiba; automatikusan nem próbálkozunk tovább.")
            raise RuntimeError(self.error)
        if self.process.poll() is not None:
            # Let the event reader consume the final auth/error record first.
            self.threads[0].join(timeout=1)
            if self.auth:
                raise AuthenticationError("A VPN-szerver visszautasította a hitelesítést.")
            raise RuntimeError(self.error or f"A VPN-motor leállt ({self.process.returncode}).")

    def close(self) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGTERM)
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=3)
        for thread in self.threads:
            thread.join(timeout=1)


def peer_allowed(address: str, allowed: tuple[ipaddress.IPv4Network, ...]) -> bool:
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return any(ip in network for network in allowed)


def vpn_socket(cfg: Config, address: str) -> socket.socket:
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote.settimeout(10)
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        remote.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, TUN_INTERFACE.encode() + b"\0")
        remote.bind((address, 0))
        remote.connect((cfg.adapter, cfg.port))
        return remote
    except Exception:
        remote.close()
        raise  # Never fall back to an unbound/direct LAN connection.


class Proxy:
    """One active C6 TCP connection; other connections are rejected immediately."""
    def __init__(self, cfg: Config, address: str, logger: Logger, *,
                 listen_port: int = LISTEN_PORT, listen_host: str = "0.0.0.0",
                 dialer: Callable[[Config, str], socket.socket] = vpn_socket):
        self.cfg, self.address, self.logger, self.dialer = cfg, address, logger, dialer
        self.stop_event = threading.Event()
        self.error: Exception | None = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.listener.bind((listen_host, listen_port))
            self.listener.listen(4)
            self.listener.settimeout(0.5)
        except Exception:
            self.listener.close()
            raise
        self.port = self.listener.getsockname()[1]
        self.lock = threading.Lock()
        self.sockets: list[socket.socket] = []
        self.worker: threading.Thread | None = None
        self.active = False
        self.last_reject_log = 0.0
        self.thread = threading.Thread(target=self.run, name="c6-listener", daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        with self.lock:
            socks = list(self.sockets)
        for sock in socks:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        self.thread.join(timeout=2)
        if self.worker:
            self.worker.join(timeout=12)  # Bounded by a pending connect's 10s timeout.

    def transfer(self, a: socket.socket, b: socket.socket) -> None:
        # Finite writes and bounded buffers; no eBUS interpretation or polling.
        with selectors.DefaultSelector() as selector:
            selector.register(a, selectors.EVENT_READ, b)
            selector.register(b, selectors.EVENT_READ, a)
            while not STOP.is_set() and not self.stop_event.is_set():
                for key, _ in selector.select(timeout=0.5):
                    data = key.fileobj.recv(65536)
                    if not data:
                        return
                    key.data.sendall(data)

    def handle(self, client: socket.socket) -> None:
        remote = None
        try:
            client.settimeout(10)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote = self.dialer(self.cfg, self.address)
            with self.lock:
                self.sockets.append(remote)
            if self.stop_event.is_set() or STOP.is_set():
                return
            self.logger.log("C6_TCP_CONNECTED – az adapter TCP-portja a VPN-en elérhető.")
            self.transfer(client, remote)
        except OSError as err:
            if not self.stop_event.is_set() and not STOP.is_set():
                self.logger.log(f"C6 TCP-kapcsolat megszakadt vagy nem jött létre (errno={err.errno}).", "WARN")
        except Exception as err:
            if not self.stop_event.is_set() and not STOP.is_set():
                self.error = err
        finally:
            client.close()
            if remote:
                remote.close()
            with self.lock:
                self.sockets = []
                self.active = False

    def run(self) -> None:
        try:
            while not STOP.is_set() and not self.stop_event.is_set():
                try:
                    client, peer = self.listener.accept()
                except socket.timeout:
                    continue
                with self.lock:
                    allowed = peer_allowed(peer[0], self.cfg.allowed)
                    reject = self.active or not allowed
                    if not reject:
                        self.active = True
                        self.sockets = [client]
                if reject:
                    client.close()
                    if time.monotonic() - self.last_reject_log >= 10:
                        message = "már van aktív C6-kliens" if allowed else "nincs az allowed_clients listában"
                        self.logger.log(f"TCP-kliens elutasítva: {peer[0]}; {message}.", "WARN")
                        self.last_reject_log = time.monotonic()
                    continue
                self.worker = threading.Thread(target=self.handle, args=(client,), daemon=True, name="c6-relay")
                self.worker.start()
        except OSError as err:
            if not self.stop_event.is_set() and not STOP.is_set():
                self.error = err


def vpn_cycle(cfg: Config, runner: Runner) -> None:
    engine: VPNProcess | None = None
    proxy: Proxy | None = None
    trace: IKETrace | None = None
    try:
        trace = start_ike_trace(cfg, runner)
        engine = VPNProcess(cfg, runner.logger)
        deadline = time.monotonic() + 50
        while not STOP.is_set():
            engine.check()
            if engine.up:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("VPN-kapcsolódási időtúllépés. Az IPsec/L2TP kapcsolat nem épült fel.")
            STOP.wait(0.25)
        if STOP.is_set():
            return
        assert engine.up is not None
        if trace:
            trace.close()
            trace = None
        address = engine.up["address"]
        for command in route_commands(cfg, address, engine.up["mtu"]):
            runner.command(command)
        engine.check()
        runner.logger.log(f"VPN_UP – {TUN_INTERFACE}, kiosztott VPN-cím: {address}.")
        targets = ", ".join(map(str, cfg.target_networks())) or "nincs célútvonal (VPN-próba)"
        runner.logger.log("ROUTE_OK – " + targets + "; DNS/default route változatlan.")
        if cfg.mode == "discover":
            scan_networks(cfg.networks, cfg.scan_ports, address, TUN_INTERFACE,
                          STOP, runner.logger.log, engine.check)
            runner.logger.log("DISCOVERY_FINISHED – egyszeri keresés kész; proxy nem indult. "
                              "A VPN lezárul; a találat kézzel adható meg adapter_ip-ként.")
            return
        if cfg.mode == "vpn_test":
            runner.logger.log("VPN_TEST_OK – a VPN felépült; adapterkapcsolat/keresés nem történt. A próba lezárul.")
            return
        proxy = Proxy(cfg, address, runner.logger)
        runner.logger.log(f"PROXY_READY – TCP {LISTEN_PORT}; ez még nem bizonyítja a C6 elérhetőségét.")
        hostname = socket.gethostname().replace("_", "-")
        runner.logger.log(f'ebusd minta (az addon adatlapján ellenőrizd a hostnevet): network_device: "ens:{hostname}:{LISTEN_PORT}"')
        while not STOP.wait(1):
            engine.check()
            if proxy.error:
                raise RuntimeError("A TCP-átjáró váratlanul leállt.")
    finally:
        # Close the relay before dismantling the VPN; no plaintext fallback.
        if proxy:
            proxy.close()
        if engine:
            engine.close()
        if trace:
            trace.close(failed=True)
        # Cleanup must not hide a prior authentication failure and trigger retries.
        try:
            for target in cfg.target_networks():
                runner.command(["ip", "-4", "route", "del", str(target), "dev", TUN_INTERFACE,
                                "metric", "5"], required=False)
        except RuntimeError:
            runner.logger.log("Az ideiglenes útvonal törlése nem ellenőrizhető; a TUN lezárása eltávolítja azt.", "WARN")
        # The TUN is destroyed when the helper closes its descriptor.


def main(options_path: Path = Path("/data/options.json"), *, check_only: bool = False) -> int:
    os.umask(0o077)
    logger = Logger()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: STOP.set())
    try:
        with options_path.open(encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict):
            raise ConfigError("A konfiguráció JSON-objektum legyen.")
        diagnostic = boolean(data, "diagnostics_only", True) or check_only
        cfg = None if diagnostic else Config.load(data)
        logger = Logger(cfg)
        runner = Runner(logger)
        logger.log(f"L2TP/IPsec C6 átjáró {VERSION} – KÍSÉRLETI; userspace PPP, saját konténerhálózat.")
        tun_preflight(runner)
        if diagnostic:
            logger.log("DIAGNOSTICS_OK – TUN/motor alapellenőrzés sikeres. VPN-bejelentkezés NEM történt.")
            if not check_only:
                logger.log("A tényleges próbához add meg a VPN-adatokat és állítsd: diagnostics_only: false.")
                STOP.wait()
            return 0
        assert cfg is not None
        out = runner.command(["ip", "-j", "-4", "address", "show"])
        check_subnet_conflict(cfg, json.loads(out.stdout))
        for target in cfg.target_networks():
            runner.command(["ip", "-4", "route", "replace", "blackhole", str(target), "metric", "42760"])
        for attempt in range(1, cfg.max_retries + 1):
            if STOP.is_set():
                return 0
            logger.log(f"VPN-kapcsolódás: {attempt}/{cfg.max_retries}.")
            try:
                vpn_cycle(cfg, runner)
                return 0
            except AuthenticationError as err:
                logger.log(str(err), "ERROR")
                return 1
            except Exception as err:
                if STOP.is_set():
                    return 0
                logger.log(str(err), "ERROR")
                if "IKE" in str(err) and "timed out" in str(err):
                    logger.log("IKE_TIMEOUT – IPsec-egyeztetési időtúllépés, még nem az adapter elérése. "
                               "Ebből önmagában nem dönthető el a hálózati, PSK- vagy kompatibilitási ok.", "WARN")
                if attempt < cfg.max_retries:
                    logger.log(f"Következő próbálkozás {cfg.retry_delay} másodperc múlva.")
                    STOP.wait(cfg.retry_delay)
        logger.log("Elértük a próbálkozási korlátot. Ellenőrzés után kézzel indítsd újra az addont.", "ERROR")
        return 1
    except Exception as err:
        logger.log(str(err), "ERROR")
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--options", type=Path, default=Path("/data/options.json"))
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    raise SystemExit(main(args.options, check_only=args.check_only))
