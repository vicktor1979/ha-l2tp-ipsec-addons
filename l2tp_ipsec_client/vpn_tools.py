"""Bounded VPN-only TCP discovery and metadata-only IKE diagnostics.

No shell commands, payload dumps, PSKs, cookies, IDs, hashes or credentials are
logged. The passive observer is restricted to one outer interface/server and
stops after the handshake. Discovery never guesses a remote address range.
"""
from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
import ipaddress
import socket
import struct
import threading
import time
from typing import Callable

PRIVATE_RANGES = tuple(ipaddress.IPv4Network(s) for s in
                       ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def discovery_networks(values: object) -> tuple[ipaddress.IPv4Network, ...]:
    if not isinstance(values, list) or not 1 <= len(values) <= 8:
        raise ValueError("A discovery_networks mezőbe 1–8 távoli IPv4/CIDR kell.")
    result = []
    for value in values:
        try:
            if not isinstance(value, str) or "/" not in value:
                raise ValueError()
            net = ipaddress.IPv4Network(value, strict=True)
        except ValueError:
            raise ValueError("Érvényes hálózati CIDR kell, például 192.168.50.0/24; ne találomra add meg.") from None
        if not any(net.subnet_of(parent) for parent in PRIVATE_RANGES):
            raise ValueError("Keresés csak megadott privát vagy 100.64.0.0/10 belső címtartományban engedélyezett.")
        if any(net.overlaps(other) for other in result):
            raise ValueError("A keresési hálózatok nem fedhetik át egymást.")
        result.append(net)
    if sum(n.num_addresses for n in result) > 1024:
        raise ValueError("Egy keresés legfeljebb 1024 címet tartalmazhat (például egy /22 vagy kisebb hálózat).")
    return tuple(result)


def discovery_ports(values: object) -> tuple[int, ...]:
    if (not isinstance(values, list) or not 1 <= len(values) <= 8
            or any(type(p) is not int or not 1 <= p <= 65535 for p in values)):
        raise ValueError("A discovery_ports 1–8 érvényes TCP-port listája legyen.")
    return tuple(dict.fromkeys(values))


def probe_tcp(host: str, port: int, address: str, interface: str, timeout: float) -> str:
    """Only TCP connect+close, no application commands or HTTP requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # A bind failure is fatal, never silently fall back to the local LAN.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        sock.bind((address, 0))
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return "open"
        except OSError as error:
            if error.errno == errno.ECONNREFUSED:
                return "refused"
            if error.errno in (errno.ENODEV, errno.EADDRNOTAVAIL, errno.EPERM, errno.EACCES):
                raise
            return "no_response"


class RateLimit:
    """Global bound of 20 connection starts/s across all scan workers."""
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self, stop: threading.Event) -> bool:
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_time - now)
            self.next_time = max(now, self.next_time) + 0.05
        return not stop.wait(delay)


def scan_networks(networks, ports, address: str, interface: str, stop: threading.Event,
                  log: Callable, check: Callable, *, timeout: float = 1.0,
                  prober: Callable = probe_tcp) -> list[dict]:
    """One explicitly scoped scan per start, no proxy and no auto-selection."""
    log("SCAN_START – tartomány: " + ", ".join(map(str, networks)) +
        "; TCP-portok: " + ",".join(map(str, ports)) + ". Csak a VPN-en.")
    cancel = threading.Event()
    limiter = RateLimit()
    hits: list[dict] = []
    hosts = [str(ip) for net in networks for ip in net.hosts() if str(ip) != address]

    def one(host):
        opened, refused = [], []
        for port in ports:
            if stop.is_set() or cancel.is_set() or not limiter.wait(cancel):
                break
            check()  # Stop if the VPN has died.
            result = prober(host, port, address, interface, timeout)
            if result == "open":
                opened.append(port)
            elif result == "refused":
                refused.append(port)
        return {"address": host, "open": opened, "refused": refused}

    with ThreadPoolExecutor(max_workers=8, thread_name_prefix="vpn-discovery") as pool:
        futures = [pool.submit(one, host) for host in hosts]
        try:
            for future in as_completed(futures):
                if stop.is_set():
                    cancel.set()
                    break
                check()
                result = future.result()
                if result["open"] or result["refused"]:
                    hits.append(result)
                    log("SCAN_HOST " + result["address"] + " open_tcp=" +
                        (",".join(map(str, result["open"])) or "-") + " refused_tcp=" +
                        (",".join(map(str, result["refused"])) or "-"))
                    if 9999 in result["open"]:
                        log("C6_CANDIDATE " + result["address"] +
                            ":9999 – csak nyitott port, nem bizonyított C6-azonosítás.")
        finally:
            cancel.set()
            for future in futures:
                future.cancel()
    hits.sort(key=lambda item: ipaddress.IPv4Address(item["address"]))
    if not stop.is_set():
        log(f"SCAN_DONE – {len(hosts)} vizsgált cím; {len(hits)} címről TCP-válasz. "
            "A válasz származhat tűzfaltól is; a csend nem bizonyítja az eszköz hiányát.")
    return hits


def parse_ike_packet(packet: bytes, server: str):
    """Parse IPv4/UDP/IKE header only, with strict lengths; never decrypt."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 15) * 4
    total = int.from_bytes(packet[2:4], "big")
    if (ihl < 20 or total > len(packet) or total < ihl + 8 or packet[9] != 17
            or int.from_bytes(packet[6:8], "big") & 0x3fff):
        return None  # Fragmented IKE is not reassembled by this observer.
    src, dst = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
    if src == server:
        direction = "RX"
    elif dst == server:
        direction = "TX"
    else:
        return None
    sport, dport, length, _ = struct.unpack_from("!HHHH", packet, ihl)
    remote_port = sport if direction == "RX" else dport
    if remote_port not in (500, 4500) or length < 8 or ihl + length > total:
        return None
    payload = packet[ihl + 8:ihl + length]
    if remote_port == 4500:
        if payload[:4] != b"\0\0\0\0":
            return None  # ESP or NAT keepalive, never log.
        payload = payload[4:]
    if len(payload) < 28 or payload[17] != 0x10:
        return None
    declared = int.from_bytes(payload[24:28], "big")
    if declared != len(payload):
        return None
    exchange = payload[18]
    if exchange not in (2, 4, 5, 32, 33):
        return None
    return dict(direction=direction, sport=sport, dport=dport, length=length,
                exchange=exchange, encrypted=bool(payload[19] & 1),
                next_payload=payload[16], cookie=payload[:8])


class IKETrace:
    """Observe the outer interface during this client's handshake only.

    Peer responses are correlated by initiator cookie (not logged). Packet
    observation is not IKE authentication or proof of server acceptance.
    """
    def __init__(self, server: str, interface: str, log: Callable):
        self.server, self.log = server, log
        self.stop = threading.Event()
        self.cookies: set[bytes] = set()
        self.counts = {"TX": 0, "RX": 0}
        self.rx4500 = 0
        self.error: str | None = None
        self.last: dict | None = None
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
        try:
            self.sock.bind((interface, 0))
            self.sock.settimeout(0.2)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except Exception:
            self.sock.close()
            raise
        self.thread = threading.Thread(target=self.run, daemon=True, name="ike-metadata")
        self.thread.start()
        log("IKE_TRACE_READY – csak IP/port/IKE-fejléc metaadatok, nincs csomagtartalom vagy titoknapló.")

    def record(self, info) -> None:
        if info["direction"] == "TX":
            self.cookies.add(info["cookie"])
        elif info["cookie"] not in self.cookies:
            return
        direction = info["direction"]
        self.counts[direction] += 1
        if direction == "RX" and info["sport"] == 4500:
            self.rx4500 += 1
        self.last = info
        if sum(self.counts.values()) <= 48:
            exchange = {2: "MainMode", 4: "Aggressive", 5: "Informational", 32: "QuickMode", 33: "NewGroup"}[info["exchange"]]
            first = {0: "none", 1: "SA", 4: "KE", 5: "ID", 8: "HASH", 11: "NOTIFY", 13: "VID", 20: "NAT-D"}.get(info["next_payload"], str(info["next_payload"]))
            self.log(f"IKE_{direction} udp={info['sport']}->{info['dport']} "
                     f"exchange={exchange} encrypted={int(info['encrypted'])} "
                     f"first_payload={first} bytes={info['length']}")

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    packet = self.sock.recv(65535)
                except socket.timeout:
                    continue
                info = parse_ike_packet(packet, self.server)
                if info:
                    self.record(info)
        except OSError as error:
            if not self.stop.is_set():
                self.error = f"errno={error.errno}"

    def close(self, *, failed: bool = False) -> None:
        self.stop.set()
        self.thread.join(timeout=1)
        self.sock.close()
        self.log(f"IKE_TRACE_SUMMARY tx={self.counts['TX']} rx={self.counts['RX']} rx4500={self.rx4500}")
        if self.error:
            self.log("IKE_TRACE_INCOMPLETE – megfigyelési hiba " + self.error, "WARN")
        elif failed and not self.counts["TX"]:
            self.log("IKE_TRACE_NO_TX – nem láttunk IKE-küldést; interfész, jogosultság vagy kliens vizsgálandó.", "WARN")
        elif failed and not self.counts["RX"]:
            self.log("IKE_TRACE_NO_REPLY – a konténernél nem láttunk illeszkedő IKE-választ. "
                     "Cím, útvonal, UDP 500/4500, NAT/tűzfal vagy néma szerver-elutasítás is okozhatja.", "WARN")
        elif failed:
            self.log("IKE_TRACE_REPLY_SEEN – IKE-válasz megfigyelhető, de ez nem bizonyítja a hitelesítést. "
                     "A szerver IPsec-naplója és a kliens kompatibilitása ellenőrizendő.", "WARN")
