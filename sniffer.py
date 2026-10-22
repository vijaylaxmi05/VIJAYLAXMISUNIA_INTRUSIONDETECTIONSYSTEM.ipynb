"""
Packet sniffer — two modes:
  1. Live capture via Scapy (requires Npcap on Windows).
  2. Simulation mode  — generates realistic synthetic packets so the
     dashboard shows real data without any special drivers.
"""

import time
import random
import threading
import struct
import socket

from . import detector
import nids as _nids_pkg

# ── Simulation data ────────────────────────────────────────────────────────────
_ATTACKER_IPS = [
    "192.168.1.101", "10.0.0.45", "172.16.0.22",
    "203.0.113.77",  "198.51.100.5", "192.0.2.88",
]
_VICTIM_IPS = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
_COMMON_PORTS = [22, 23, 80, 443, 3306, 5432, 8080, 8443, 21, 25, 110, 3389]

# Attack scenarios: (name, weight)
_SCENARIOS = [
    ("syn_flood",   20),
    ("port_scan",   20),
    ("icmp_flood",  15),
    ("null_scan",    5),
    ("xmas_scan",    5),
    ("normal",      35),
]
_WEIGHTS = [w for _, w in _SCENARIOS]
_NAMES   = [n for n, _ in _SCENARIOS]


class _FakePacket:
    """Minimal packet object that mimics Scapy's packet interface."""

    def __init__(self, src, dst, proto="TCP", sport=None, dport=None,
                 tcp_flags=0x02, icmp=False):
        self._layers = {"IP": True}
        self.src = src
        self.dst = dst
        self.proto = proto
        self.sport = sport or random.randint(1024, 65535)
        self.dport = dport or random.choice(_COMMON_PORTS)
        self.tcp_flags = tcp_flags
        self._icmp = icmp

    # Scapy-style layer checks --------------------------------------------------
    def __contains__(self, layer_cls):
        name = getattr(layer_cls, "__name__", str(layer_cls))
        if name == "IP":
            return True
        if name == "TCP":
            return self.proto == "TCP"
        if name == "UDP":
            return self.proto == "UDP"
        if name == "ICMP":
            return self._icmp
        return False

    def __getitem__(self, layer_cls):
        name = getattr(layer_cls, "__name__", str(layer_cls))
        if name == "IP":
            return _IPLayer(self.src, self.dst)
        if name in ("TCP", "UDP"):
            return _TransportLayer(self.sport, self.dport, self.tcp_flags)
        if name == "ICMP":
            return _ICMPLayer()
        raise KeyError(name)


class _IPLayer:
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst


class _TransportLayer:
    def __init__(self, sport, dport, flags):
        self.sport = sport
        self.dport = dport
        self.flags  = flags


class _ICMPLayer:
    pass


# ── Simulation runner ──────────────────────────────────────────────────────────

def _make_packet(scenario: str) -> _FakePacket:
    src = random.choice(_ATTACKER_IPS)
    dst = random.choice(_VICTIM_IPS)

    if scenario == "syn_flood":
        return _FakePacket(src, dst, proto="TCP", tcp_flags=0x02)

    if scenario == "port_scan":
        return _FakePacket(src, dst, proto="TCP",
                           dport=random.randint(1, 65535), tcp_flags=0x02)

    if scenario == "icmp_flood":
        return _FakePacket(src, dst, proto="ICMP", icmp=True)

    if scenario == "null_scan":
        return _FakePacket(src, dst, proto="TCP", tcp_flags=0x00)

    if scenario == "xmas_scan":
        return _FakePacket(src, dst, proto="TCP", tcp_flags=0x29)

    # normal — mix of TCP/UDP
    proto = random.choice(["TCP", "UDP"])
    return _FakePacket(src, dst, proto=proto,
                       dport=random.choice(_COMMON_PORTS), tcp_flags=0x18)


def _simulate(rate: float = 0.05):
    """
    Generate synthetic packets at `rate` seconds per packet (~20 pkt/s).
    Bursts every ~10 s to trigger detection rules.
    Pauses when _nids_pkg.sniffer_running is False.
    """
    print("[*] Running in SIMULATION mode — generating synthetic traffic...")
    store = _nids_pkg.alert_store
    t0 = time.time()

    while True:
        # Honour stop/resume flag — poll every 0.2 s while paused
        if not _nids_pkg.sniffer_running:
            time.sleep(0.2)
            continue

        # Every ~10 s trigger a realistic burst attack
        elapsed = time.time() - t0
        if int(elapsed) % 10 == 0 and int(elapsed) > 0:
            scenario = random.choices(_NAMES, weights=_WEIGHTS, k=1)[0]
            burst = 120 if "flood" in scenario else 20
            print(f"[SIM] Burst: {scenario} x{burst}")
            for _ in range(burst):
                if not _nids_pkg.sniffer_running:
                    break
                pkt = _make_packet(scenario)
                detector.analyze(pkt, store)
            time.sleep(1)          # avoid re-triggering same second
        else:
            scenario = random.choices(_NAMES, weights=_WEIGHTS, k=1)[0]
            pkt = _make_packet(scenario)
            detector.analyze(pkt, store)
            time.sleep(rate)


# ── Live capture ───────────────────────────────────────────────────────────────

def _live(interface=None):
    """Capture real packets with Scapy."""
    try:
        from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, ICMP
    except ImportError:
        print("[!] Scapy not installed. Falling back to simulation mode.")
        _simulate()
        return

    store = _nids_pkg.alert_store

    def _cb(packet):
        detector.analyze(packet, store)

    print(f"[*] Live capture on interface: {interface or 'default'}")
    try:
        scapy_sniff(iface=interface, prn=_cb, store=False, count=0)
    except Exception as e:
        print(f"[!] Scapy capture failed: {e}")
        print("[*] Falling back to simulation mode.")
        _simulate()


# ── Public API ─────────────────────────────────────────────────────────────────

def start(interface=None, simulate=False):
    """
    Start the sniffer.
    :param interface: NIC name for live capture.
    :param simulate:  If True, run simulation regardless of Npcap.
    """
    if simulate:
        _simulate()
    else:
        _live(interface)
