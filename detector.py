"""
Detection engine — applies all rules to each packet.
"""

from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
import time

# ── sliding-window counters ────────────────────────────────────────────────────
# { src_ip: [(timestamp, dst_port), ...] }
_syn_tracker: dict = defaultdict(list)
_icmp_tracker: dict = defaultdict(list)
_port_scan_tracker: dict = defaultdict(set)  # { src_ip: {dst_ports} }

WINDOW = 5          # seconds
SYN_THRESHOLD = 100  # SYN packets per WINDOW → SYN flood
ICMP_THRESHOLD = 50  # ICMP packets per WINDOW → ICMP flood
PORT_SCAN_THRESHOLD = 15  # distinct ports per WINDOW → port scan


def _prune(events: list, now: float) -> list:
    return [e for e in events if now - e[0] < WINDOW]


def analyze(packet, store):
    """Analyse a single packet against all detection rules."""
    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    now = time.time()

    # ── Rule 1: SYN Flood ──────────────────────────────────────────────────────
    if TCP in packet and packet[TCP].flags == 0x02:  # SYN only
        _syn_tracker[src] = _prune(_syn_tracker[src], now)
        _syn_tracker[src].append((now, packet[TCP].dport))
        if len(_syn_tracker[src]) > SYN_THRESHOLD:
            store.add("SYN Flood", src, dst,
                      f"{len(_syn_tracker[src])} SYNs in {WINDOW}s")
            _syn_tracker[src].clear()

    # ── Rule 2: Port Scan ──────────────────────────────────────────────────────
    if TCP in packet or UDP in packet:
        proto = TCP if TCP in packet else UDP
        dport = packet[proto].dport
        # record (time, port) pairs
        events = _port_scan_tracker.get(src, None)
        if events is None:
            _port_scan_tracker[src] = {}
        _port_scan_tracker[src][dport] = now
        # prune old ports
        _port_scan_tracker[src] = {
            p: t for p, t in _port_scan_tracker[src].items() if now - t < WINDOW
        }
        if len(_port_scan_tracker[src]) > PORT_SCAN_THRESHOLD:
            store.add("Port Scan", src, dst,
                      f"{len(_port_scan_tracker[src])} distinct ports in {WINDOW}s")
            _port_scan_tracker[src].clear()

    # ── Rule 3: ICMP Flood ─────────────────────────────────────────────────────
    if ICMP in packet:
        _icmp_tracker[src] = _prune(_icmp_tracker[src], now)
        _icmp_tracker[src].append((now, 0))
        if len(_icmp_tracker[src]) > ICMP_THRESHOLD:
            store.add("ICMP Flood", src, dst,
                      f"{len(_icmp_tracker[src])} ICMP pkts in {WINDOW}s")
            _icmp_tracker[src].clear()

    # ── Rule 4: Null Scan (all TCP flags = 0) ─────────────────────────────────
    if TCP in packet and packet[TCP].flags == 0x00:
        store.add("Null Scan", src, dst, f"dport={packet[TCP].dport}")

    # ── Rule 5: Xmas Scan (FIN+PSH+URG) ──────────────────────────────────────
    if TCP in packet and (packet[TCP].flags & 0x29) == 0x29:
        store.add("Xmas Scan", src, dst, f"dport={packet[TCP].dport}")
