# -------------------------------------------------
#  AI-IDS  -  Packet Capture Engine (Scapy sniff)
#  Captures live packets and feeds raw data into
#  the per-node traffic buffer for aggregation.
# -------------------------------------------------
import asyncio
import threading
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import sniff, IP, TCP, UDP

# Import detection control
from backend.state import state


# -- Shared in-memory raw packet buffer -----------
# Structure: { ip_src: [ {dst, proto, length, ts}, ... ] }
_raw_buffer: dict[str, list[dict]] = defaultdict(list)
_buffer_lock = threading.Lock()


def get_raw_buffer() -> dict[str, list[dict]]:
    """Return a snapshot of the buffer and clear it."""
    with _buffer_lock:
        snapshot = dict(_raw_buffer)
        _raw_buffer.clear()
    return snapshot


# -- Packet handler (called per packet by Scapy) --
def _handle_packet(pkt):
    # Only capture packets when detection is enabled
    if not state.detection_enabled:
        return
        
    if IP not in pkt:
        return

    src  = pkt[IP].src
    dst  = pkt[IP].dst
    size = len(pkt)
    ts   = datetime.now(timezone.utc).isoformat()

    proto = "other"
    if TCP in pkt:
        proto = "tcp"
    elif UDP in pkt:
        proto = "udp"

    record = {
        "dst":    dst,
        "proto":  proto,
        "length": size,
        "ts":     ts,
    }

    with _buffer_lock:
        _raw_buffer[src].append(record)


# -- Background sniffer thread ---------------------
def _sniffer_thread():
    print("[Sniffer] Starting packet capture on all interfaces...")
    sniff(
        prn=_handle_packet,
        store=False,       # don't keep in memory — we handle it ourselves
        filter="ip",       # only IP packets
    )


def start_sniffer():
    """Launch the sniffer in a daemon thread (non-blocking)."""
    t = threading.Thread(target=_sniffer_thread, daemon=True)
    t.start()
    print("[Sniffer] (OK) Sniffer thread started")
