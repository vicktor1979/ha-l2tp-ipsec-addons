#!/usr/bin/env python3
"""Experimental HA L2TP/IPsec client and single-client, VPN-bound TCP proxy.

Own network namespace only. No shell command interpolation and no host routes.
Credentials are rendered into private files under /tmp (HA tmpfs).
"""
from __future__ import annotations

import array
import base64
import contextlib
import fcntl
import gzip
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

CONNECTION = "c6vpn"
PPP_INTERFACE = "vpnppp0"
LISTEN_PORT = 9999
RUNTIME = Path("/tmp/ha-l2tp")
CONTROL = Path("/run/xl2tpd/l2tp-control")
STOP = threading.Event()


class ConfigError(ValueError):
    pass


def clean_text(value: Any, field: str, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"A(z) {field} mező szöveg legyen.")
    if required and not value:
        raise ConfigError(f"Hiányzó beállítás: {field}.")
    if len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError(f"A(z) {field} mező túl hosszú vagy vezérlőkaraktert tartalmaz.")
    return value


def unicast_ipv4(value: Any, field: str) -> str:
    value = clean_text(value, field)
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ConfigError(f"A(z) {field} mezőbe IPv4-cím kell, nem URL vagy hálózati tartomány.") from None
    if addr.is_unspecified or addr.is_loopback or addr.is_multicast or int(addr) == 0xffffffff:
        raise ConfigError(f"A(z) {field} mezőben nem használható ez a címfajta.")
    return str(addr)


def number(data: dict[str, Any], name: str, default: int, low: int, high: int) -> int:
    value = data.get(name, default)
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"A(z) {name} egész szám legyen {low} és {high} között.")
    return value


def boolean(data: dict[str, Any], name: str, default: bool) -> bool:
    value = data.get(name, default)
    if type(value) is not bool:
        raise ConfigError(f"A(z) {name} true vagy false legyen.")
    return value


@dataclass(frozen=True, repr=False)
class Config:
    server: str
    username: str
    password: str
    psk: str
    adapter: str
    port: int
    auth: str
    legacy: bool
    mtu: int
    retry_delay: int
    max_retries: int
    allowed: tuple[ipaddress.IPv4Network, ...]

    @classmethod
    def load(cls, data: dict[str, Any]) -> "Config":
        server = unicast_ipv4(data.get("vpn_server", ""), "vpn_server")
        adapter = unicast_ipv4(data.get("adapter_ip", ""), "adapter_ip")
        if server == adapter:
            raise ConfigError("A VPN-szerver és az adapter címe nem lehet azonos ebben a verzióban.")
        auth = data.get("ppp_auth", "mschapv2")
        if auth not in {"mschapv2", "chap", "pap", "auto"}:
            raise ConfigError("Ismeretlen ppp_auth érték.")
        nets = data.get("allowed_clients", ["172.30.32.0/23", "127.0.0.1/32"])
        if not isinstance(nets, list) or not 1 <= len(nets) <= 64:
            raise ConfigError("Az allowed_clients 1–64 darab IPv4-cím vagy CIDR-hálózat listája legyen.")
        allowed = []
        for item in nets:
            try:
                net = ipaddress.IPv4Network(clean_text(item, "allowed_clients"), strict=False)
            except ValueError:
                raise ConfigError("Hibás IPv4-cím vagy CIDR az allowed_clients listában.") from None
            if net.prefixlen == 0:
                raise ConfigError("A 0.0.0.0/0 nem engedélyezett az allowed_clients listában.")
            allowed.append(net)
        return cls(
            server, clean_text(data.get("vpn_username", ""), "vpn_username"),
            clean_text(data.get("vpn_password", ""), "vpn_password"),
            clean_text(data.get("vpn_psk", ""), "vpn_psk"), adapter,
            number(data, "adapter_port", 9999, 1, 65535), auth,
            boolean(data, "legacy_compatibility", False),
            number(data, "mtu", 1400, 1280, 1460),
            number(data, "retry_delay", 60, 30, 600),
            number(data, "max_retries", 3, 1, 10), tuple(allowed),
        )


def ppp_quote(value: str) -> str:
    """pppd options lexer: quote backslash and double quote, reject controls."""
    value = clean_text(value, "PPP-hitelesítési adat")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def configurations(cfg: Config) -> dict[str, str]:
    ike = ["aes256-sha256-modp2048", "aes128-sha256-modp2048",
           "aes256-sha1-modp2048", "aes128-sha1-modp2048"]
    esp = ["aes256-sha256", "aes128-sha256", "aes256-sha1", "aes128-sha1"]
    if cfg.legacy:
        ike += ["aes256-sha1-modp1024", "aes128-sha1-modp1024", "3des-sha1-modp1024"]
        esp += ["3des-sha1"]
    ipsec = f"""config setup
    uniqueids=no
conn {CONNECTION}
    keyexchange=ikev1
    type=transport
    authby=psk
    left=%defaultroute
    leftprotoport=17/1701
    right={cfg.server}
    rightid=%any
    rightprotoport=17/1701
    ike={','.join(ike)}!
    esp={','.join(esp)}!
    forceencaps=yes
    fragmentation=yes
    keyingtries=1
    dpdaction=clear
    dpddelay=30s
    dpdtimeout=90s
    ikelifetime=8h
    lifetime=1h
    rekey=yes
    auto=add
"""
    ppp = ["noauth", "noipdefault", "ipcp-accept-local", "ipcp-accept-remote",
           "nodefaultroute", "noipv6", "hide-password", "nodetach",
           "noccp", "nobsdcomp", "nodeflate", "novj", "refuse-eap",
           f"ifname {PPP_INTERFACE}", f"mtu {cfg.mtu}", f"mru {cfg.mtu}",
           "lcp-echo-interval 20", "lcp-echo-failure 3", "connect-delay 1000",
           "logfd 2", f"user {ppp_quote(cfg.username)}", f"password {ppp_quote(cfg.password)}"]
    refuses = {
        "mschapv2": ["refuse-pap", "refuse-chap", "refuse-mschap"],
        "chap": ["refuse-pap", "refuse-mschap", "refuse-mschap-v2"],
        "pap": ["refuse-chap", "refuse-mschap", "refuse-mschap-v2"],
        "auto": [],
    }
    ppp.extend(refuses[cfg.auth])
    xl2tp = f"""[global]
port = 1701
access control = yes

[lac {CONNECTION}]
lns = {cfg.server}
pppoptfile = {RUNTIME}/ppp-options
ppp debug = no
require authentication = no
autodial = no
redial = no
length bit = yes
"""
    # Base64 form avoids ipsec.secrets quote/backslash interpolation problems.
    psk = base64.b64encode(cfg.psk.encode("utf-8")).decode("ascii")
    return {"ipsec.conf": ipsec, "ipsec.secrets": f": PSK 0s{psk}\n",
            "ppp-options": "\n".join(ppp) + "\n", "xl2tpd.conf": xl2tp}


def strongswan_configuration() -> str:
    return """charon {
    load_modular = yes
    install_routes = no
    install_virtual_ip = no
    plugins {
        include /etc/strongswan.d/charon/*.conf
        resolve {
            load = no
        }
    }
    filelog {
        stdout {
            path = /dev/stdout
            default = 1
            flush_line = yes
        }
    }
}
"""


class Logger:
    def __init__(self, cfg: Config | None = None):
        self.lock = threading.Lock()
        self.auth_failure = threading.Event()
        self.secrets: list[str] = []
        if cfg:
            for text in (cfg.psk, cfg.password, cfg.username):
                self.secrets.extend([text, ppp_quote(text)[1:-1]])
            self.secrets.extend([base64.b64encode(cfg.psk.encode()).decode(), cfg.psk.encode().hex()])
            self.secrets = sorted(set(self.secrets), key=len, reverse=True)

    def redact(self, message: str) -> str:
        for secret in self.secrets:
            if secret:
                message = message.replace(secret, "[REDACTED]")
        return message

    def log(self, message: str, level: str = "INFO") -> None:
        with self.lock:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [{level}] {self.redact(message)}", flush=True)

    def daemon_line(self, prefix: str, line: str) -> None:
        lower = line.lower()
        if any(t in lower for t in ("chap authentication failed", "pap authentication failed",
                                    "authentication failed", "failed to authenticate ourselves")):
            self.auth_failure.set()
        self.log(f"{prefix}: {line.rstrip()}")


class Runner:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.children: dict[str, subprocess.Popen[str]] = {}

    def command(self, args: list[str], timeout: float = 10, *, required: bool = True,
                report: bool = False) -> subprocess.CompletedProcess[str]:
        try:
            out = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout,
                                 env={**os.environ, "LC_ALL": "C"}, check=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Időtúllépés: {args[0]}.") from None
        if report or (required and out.returncode):
            for line in (out.stdout + out.stderr).splitlines():
                self.logger.daemon_line(args[0], line)
        if required and out.returncode:
            raise RuntimeError(f"A(z) {args[0]} parancs hibakódja: {out.returncode}.")
        return out

    def start(self, name: str, args: list[str]) -> None:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, errors="replace", bufsize=1, start_new_session=True,
                                   env={**os.environ, "LC_ALL": "C"})
        self.children[name] = process
        def drain() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                self.logger.daemon_line(name, line)
            process.stdout.close()
        threading.Thread(target=drain, name=f"log-{name}", daemon=True).start()

    def stop(self, name: str) -> None:
        process = self.children.pop(name, None)
        if process is None:
            return
        # Kill the process group, including a foreground pppd child.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)

    def check(self) -> None:
        for name, process in self.children.items():
            if process.poll() is not None:
                raise RuntimeError(f"A(z) {name} folyamat leállt ({process.returncode}).")
        if self.logger.auth_failure.is_set():
            raise RuntimeError("Hitelesítési hiba; a fiók védelmében nem próbálkozunk tovább.")


def kernel_preflight(runner: Runner) -> None:
    log = runner.logger.log
    log(f"Kernel: {os.uname().release}; architektúra: {os.uname().machine}.")
    keys = ("CONFIG_PPP", "CONFIG_PPP_ASYNC", "CONFIG_PPPOL2TP", "CONFIG_L2TP",
            "CONFIG_XFRM_USER", "CONFIG_INET_ESP", "CONFIG_NETFILTER_XT_MATCH_POLICY")
    try:
        with gzip.open("/proc/config.gz", "rt", errors="replace") as src:
            kernel_config = src.read()
        for key in keys:
            match = re.search(rf"^{key}=(.+)$", kernel_config, re.M)
            unset = f"# {key} is not set" in kernel_config
            value = match.group(1) if match else ("n" if unset else "ismeretlen")
            log(f"{key}={value}")
    except (OSError, EOFError):
        log("A /proc/config.gz nem olvasható; tényleges eszközpróba következik.", "WARN")

    # Existing, distribution-provided modules only. Never install/download a module.
    for module in ("ppp_generic", "ppp_async", "pppox", "l2tp_ppp", "xfrm_user", "esp4", "xt_policy"):
        runner.command(["modprobe", "-q", module], required=False)

    dev = Path("/dev/ppp")
    if not dev.exists():
        try:
            os.mknod(dev, stat.S_IFCHR | 0o600, os.makedev(108, 0))
        except OSError:
            raise RuntimeError("A /dev/ppp nem hozható létre. Ellenőrizd a Védett mód/jogosultság beállítást.") from None
    try:
        fd = os.open(dev, os.O_RDWR | os.O_CLOEXEC)
        try:
            unit = array.array("i", [-1])
            # _IOWR('t', 62, int), from Linux uapi/linux/ppp-ioctl.h.
            fcntl.ioctl(fd, 0xC004743E, unit, True)
        finally:
            os.close(fd)  # The temporary PPP unit is destroyed here.
    except OSError as err:
        raise RuntimeError(f"PPP kernel-/hozzáférési próba sikertelen (errno={err.errno}). "
                           "A hiányzó kernel-PPP támogatást az addon nem tudja pótolni.") from None
    log("PPP_KERNEL_OK – PPP-eszköz megnyitása és ideiglenes interfész létrehozása sikeres.")
    runner.command(["ip", "xfrm", "policy", "list"])
    # A detached chain checks policy-match support without filtering any traffic.
    runner.command(["iptables", "-w", "5", "-N", "HA_C6_DIAG"])
    try:
        runner.command(["iptables", "-w", "5", "-A", "HA_C6_DIAG", "-m", "policy",
                        "--dir", "out", "--pol", "ipsec", "-j", "RETURN"])
    finally:
        runner.command(["iptables", "-w", "5", "-F", "HA_C6_DIAG"], required=False)
        runner.command(["iptables", "-w", "5", "-X", "HA_C6_DIAG"], required=False)
    log("XFRM_POLICY_OK – IPsec-házirend és policy-tűzfalszabály létrehozható.")


def secure_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)


def write_configuration(cfg: Config) -> None:
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RUNTIME, 0o700)
    for name, text in configurations(cfg).items():
        secure_write(RUNTIME / name, text)
    for name in ("ipsec.conf", "ipsec.secrets"):
        link = Path("/etc") / name
        link.unlink(missing_ok=True)
        link.symlink_to(RUNTIME / name)
    secure_write(Path("/etc/strongswan.conf"), strongswan_configuration())


def firewall_commands(cfg: Config) -> list[list[str]]:
    return [
        # No unencrypted L2TP may leave or enter this container, even if an SA drops.
        ["iptables", "-w", "5", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "1701",
         "-m", "policy", "--dir", "out", "--pol", "none", "-j", "REJECT"],
        ["iptables", "-w", "5", "-I", "INPUT", "1", "-p", "udp", "--sport", "1701",
         "-m", "policy", "--dir", "in", "--pol", "none", "-j", "DROP"],
        # Defense in depth alongside SO_BINDTODEVICE in the proxy.
        ["iptables", "-w", "5", "-I", "OUTPUT", "1", "-d", cfg.adapter, "-p", "tcp",
         "--dport", str(cfg.port), "!", "-o", PPP_INTERFACE, "-j", "REJECT"],
    ]


def child_sa_installed(status: str) -> bool:
    return bool(re.search(rf"\b{CONNECTION}\{{\d+\}}:.*\bINSTALLED,\s*TRANSPORT\b", status))


def interface_address(runner: Runner) -> str | None:
    out = runner.command(["ip", "-j", "-4", "addr", "show", "dev", PPP_INTERFACE], required=False)
    if out.returncode:
        return None
    for item in json.loads(out.stdout or "[]"):
        for addr in item.get("addr_info", []):
            if addr.get("family") == "inet":
                return addr["local"]
    return None


def peer_allowed(address: str, allowed: tuple[ipaddress.IPv4Network, ...]) -> bool:
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False
    return any(ip in network for network in allowed)


class Proxy:
    """Single eBUS connection; no protocol inspection, caching, or adapter probes."""
    def __init__(self, cfg: Config, logger: Logger):
        self.cfg, self.logger = cfg, logger
        self.stop_event = threading.Event()
        self.error: Exception | None = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("0.0.0.0", LISTEN_PORT))
        self.listener.listen(1)
        self.listener.settimeout(1)
        self.sockets: list[socket.socket] = []
        self.thread = threading.Thread(target=self.run, name="c6-tcp-proxy", daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        for sock in list(self.sockets):
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        self.thread.join(timeout=3)

    def transfer(self, source: socket.socket, destination: socket.socket) -> None:
        # Small eBUS stream: sendall with a finite timeout applies backpressure.
        with selectors.DefaultSelector() as selector:
            selector.register(source, selectors.EVENT_READ, destination)
            selector.register(destination, selectors.EVENT_READ, source)
            while not STOP.is_set() and not self.stop_event.is_set():
                for key, _ in selector.select(timeout=1):
                    chunk = key.fileobj.recv(65536)
                    if not chunk:
                        return
                    key.data.sendall(chunk)

    def run(self) -> None:
        try:
            while not STOP.is_set() and not self.stop_event.is_set():
                try:
                    client, peer = self.listener.accept()
                except socket.timeout:
                    continue
                if not peer_allowed(peer[0], self.cfg.allowed):
                    self.logger.log(f"TCP-hozzáférés tiltva erről a címről: {peer[0]}.", "WARN")
                    client.close()
                    continue
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sockets = [client, remote]
                try:
                    for sock in self.sockets:
                        sock.settimeout(10)
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    # Bind before connecting. Never retry on the ordinary LAN interface.
                    remote.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                      PPP_INTERFACE.encode("ascii") + b"\0")
                    remote.connect((self.cfg.adapter, self.cfg.port))
                    self.logger.log("C6_TCP_CONNECTED – a TCP-kapcsolat az adapterhez létrejött.")
                    self.transfer(client, remote)
                except OSError as err:
                    if not self.stop_event.is_set() and not STOP.is_set():
                        self.logger.log(f"C6 TCP-kapcsolat megszakadt vagy nem jött létre (errno={err.errno}).", "WARN")
                finally:
                    client.close()
                    remote.close()
                    self.sockets = []
        except Exception as err:
            if not self.stop_event.is_set() and not STOP.is_set():
                self.error = err
                self.logger.log(f"TCP-átjáró leállt: {type(err).__name__}.", "ERROR")


def wait_until(runner: Runner, predicate: Any, seconds: int, failure: str) -> Any:
    deadline = time.monotonic() + seconds
    while not STOP.is_set() and time.monotonic() < deadline:
        runner.check()
        value = predicate()
        if value:
            return value
        STOP.wait(1)
    raise RuntimeError("Leállítás kérve." if STOP.is_set() else failure)


def cleanup_session(runner: Runner, proxy: Proxy | None) -> None:
    if proxy:
        proxy.close()
    runner.stop("xl2tpd")
    with contextlib.suppress(Exception):
        runner.command(["ipsec", "down", CONNECTION], required=False, timeout=5)
    with contextlib.suppress(Exception):
        runner.command(["ipsec", "stop"], required=False, timeout=5)
    runner.stop("ipsec")
    CONTROL.unlink(missing_ok=True)


def vpn_cycle(cfg: Config, runner: Runner) -> float:
    proxy: Proxy | None = None
    ready_at = 0.0
    try:
        runner.start("ipsec", ["ipsec", "start", "--nofork"])
        wait_until(runner, lambda: Path("/run/charon.ctl").exists(), 20,
                   "Az IPsec vezérlősocket nem jelent meg.")
        runner.command(["ipsec", "up", CONNECTION], timeout=90, report=True)
        def installed() -> bool:
            result = runner.command(["ipsec", "status", CONNECTION], required=False)
            return result.returncode == 0 and child_sa_installed(result.stdout)
        wait_until(runner, installed, 10, "Nincs telepített IPsec transport SA.")
        runner.logger.log("IPSEC_UP – titkosított transport SA létrejött.")
        CONTROL.parent.mkdir(parents=True, exist_ok=True)
        CONTROL.unlink(missing_ok=True)
        runner.start("xl2tpd", ["xl2tpd", "-D", "-c", str(RUNTIME / "xl2tpd.conf"),
                                "-C", str(CONTROL), "-p", "/run/xl2tpd/xl2tpd.pid"])
        wait_until(runner, lambda: CONTROL.exists() and stat.S_ISFIFO(CONTROL.stat().st_mode),
                   15, "Az L2TP vezérlőcsatorna nem jelent meg.")
        descriptor = os.open(CONTROL, os.O_WRONLY | os.O_NONBLOCK)
        try:
            os.write(descriptor, f"c {CONNECTION}\n".encode("ascii"))
        finally:
            os.close(descriptor)
        address = wait_until(runner, lambda: interface_address(runner), 60,
                             "A PPP-kapcsolat nem kapott IP-címet. Nézd meg a hitelesítés/L2TP naplóját.")
        runner.command(["ip", "route", "replace", cfg.adapter + "/32", "dev", PPP_INTERFACE])
        ready_at = time.monotonic()
        runner.logger.log(f"VPN_UP – {PPP_INTERFACE}, kiosztott VPN-cím: {address}.")
        proxy = Proxy(cfg, runner.logger)
        hostname = socket.gethostname().replace("_", "-")
        runner.logger.log(f"PROXY_READY – belső TCP {LISTEN_PORT}; még nem bizonyítja az adapter elérhetőségét.")
        runner.logger.log(f'ebusd minta, az addon adatlapján ellenőrzött hostnévvel: network_device: "ens:{hostname}:{LISTEN_PORT}"')
        while not STOP.wait(5):
            runner.check()
            if proxy.error:
                raise RuntimeError("A TCP-átjáró váratlanul leállt.")
            if interface_address(runner) != address or not installed():
                raise RuntimeError("A PPP vagy IPsec kapcsolat megszakadt.")
    finally:
        cleanup_session(runner, proxy)
    return time.monotonic() - ready_at if ready_at else 0.0


def main(options_path: Path = Path("/data/options.json")) -> int:
    os.umask(0o077)
    logger = Logger()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: STOP.set())
    try:
        with options_path.open(encoding="utf-8") as src:
            data = json.load(src)
        if not isinstance(data, dict):
            raise ConfigError("A konfiguráció JSON-objektum legyen.")
        diagnostic = boolean(data, "diagnostics_only", True)
        cfg = None if diagnostic else Config.load(data)
        logger = Logger(cfg)
        runner = Runner(logger)
        logger.log("L2TP/IPsec C6 átjáró 0.1.0 – KÍSÉRLETI; saját konténerhálózat, nincs HA-default-route módosítás.")
        kernel_preflight(runner)
        if diagnostic:
            logger.log("DIAGNOSTICS_OK – az alap kernel- és jogosultságpróbák sikeresek. VPN-csatlakozás NEM történt.")
            logger.log("Add meg a VPN és adapter adatait, állítsd a diagnostics_only értékét false-ra, és indítsd újra.")
            STOP.wait()
            return 0
        assert cfg is not None
        # A target in the addon's own Docker subnet would reroute local client responses.
        existing = runner.command(["ip", "-j", "-4", "addr", "show"]).stdout
        for iface in json.loads(existing):
            if iface.get("ifname") == "lo":
                continue
            for item in iface.get("addr_info", []):
                if item.get("family") == "inet":
                    net = ipaddress.IPv4Network(f"{item['local']}/{item['prefixlen']}", strict=False)
                    if ipaddress.IPv4Address(cfg.adapter) in net:
                        raise ConfigError("Az adapter címe ütközik az addon belső konténerhálózatával.")
        if cfg.legacy:
            logger.log("Régi IPsec-algoritmusok engedélyezve (MODP1024 / 3DES). Csak indokolt kompatibilitáshoz.", "WARN")
        write_configuration(cfg)
        for args in firewall_commands(cfg):
            runner.command(args)
        for attempt in range(1, cfg.max_retries + 1):
            if STOP.is_set():
                return 0
            logger.log(f"VPN-kapcsolódás: {attempt}/{cfg.max_retries}.")
            try:
                vpn_cycle(cfg, runner)
                return 0
            except Exception as err:
                if STOP.is_set():
                    return 0
                logger.log(str(err), "ERROR")
                if logger.auth_failure.is_set():
                    logger.log("Hitelesítési hiba után nincs automatikus újrapróbálkozás. Ellenőrizd a helyi adatokat.", "ERROR")
                    return 1
                if attempt < cfg.max_retries:
                    logger.log(f"Következő próbálkozás {cfg.retry_delay} másodperc múlva.")
                    STOP.wait(cfg.retry_delay)
        logger.log("Elértük a próbálkozási korlátot. Ellenőrzés után kézzel indítsd újra az addont.", "ERROR")
        return 1
    except Exception as err:
        logger.log(str(err), "ERROR")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
