# -------------------------------------------------
#  AI-IDS  -  Feature Aggregator
#  Every AGGREGATE_INTERVAL seconds, pulls raw
#  packet data from the sniffer buffer and computes
#  per-node ML features.
# -------------------------------------------------
import asyncio
from datetime import datetime, timezone

from backend.sniffer.packet_capture import get_raw_buffer
from database.mongo_client import metrics_col
from backend.state import state

AGGREGATE_INTERVAL = 5   # seconds


def _compute_features(ip: str, packets: list[dict]) -> dict:
    """Compute ML-ready features from a list of raw packet records."""
    total        = len(packets)
    tcp_count    = sum(1 for p in packets if p["proto"] == "tcp")
    udp_count    = sum(1 for p in packets if p["proto"] == "udp")
    sizes        = [p["length"] for p in packets]
    destinations = {p["dst"] for p in packets}

    return {
        "ip":                  ip,
        "packets_per_sec":     round(total / AGGREGATE_INTERVAL, 2),
        "avg_packet_size":     round(sum(sizes) / total, 2) if total else 0,
        "unique_destinations": len(destinations),
        "tcp_ratio":           round(tcp_count / total, 3) if total else 0,
        "udp_ratio":           round(udp_count / total, 3) if total else 0,
        "connection_count":    total,
        "timestamp":           datetime.now(timezone.utc).isoformat(),
    }


async def run_aggregator(on_features_ready_fn):
    """
    Continuous aggregation loop.

    on_features_ready_fn: async coroutine called with a features dict
                          for every active node — feeds the ML detector.
    """
    col = metrics_col()
    print(f"[Aggregator] Running every {AGGREGATE_INTERVAL}s")

    while True:
        await asyncio.sleep(AGGREGATE_INTERVAL)

        if not state.detection_enabled:
            continue

        raw = get_raw_buffer()   # { ip: [packet_records] }

        for ip, packets in raw.items():
            if not packets:
                continue

            features = _compute_features(ip, packets)

            # -- Persist to MongoDB --------------------
            await col.insert_one({**features})

            # -- Pass to ML detector -------------------
            await on_features_ready_fn(features)
