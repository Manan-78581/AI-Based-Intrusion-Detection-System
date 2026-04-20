# -------------------------------------------------
#  AI-IDS  -  Alert Engine
#  Triggered when ML flags a node as "malicious".
#  Stores alert in MongoDB, pushes via WebSocket,
#  and appends to a local log file.
# -------------------------------------------------
import os
import logging
from datetime import datetime, timezone

from database.mongo_client import alerts_col, nodes_col

LOG_PATH = "logs/alerts.log"
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.WARNING,
    format="%(asctime)s  %(message)s",
)


async def process_detection(features: dict, anomaly_score: float,
                             risk_level: str, ws_broadcast_fn):
    """
    Called by main pipeline after every ML score.
    Only acts when risk_level is 'malicious'.
    Always updates the node document in MongoDB.
    """
    ip  = features["ip"]
    now = datetime.now(timezone.utc).isoformat()

    # -- Always update node risk in MongoDB --------
    await nodes_col().update_one(
        {"ip": ip},
        {"$set": {
            "anomaly_score": anomaly_score,
            "risk_level":    risk_level,
            "last_seen":     now,
        }},
        upsert=True,
    )

    # -- Broadcast real-time traffic update --------
    await ws_broadcast_fn({
        "event": "traffic_update",
        "data": {
            "ip":            ip,
            "anomaly_score": anomaly_score,
            "risk_level":    risk_level,
            "packets_per_sec":     features.get("packets_per_sec", 0),
            "avg_packet_size":     features.get("avg_packet_size", 0),
            "unique_destinations": features.get("unique_destinations", 0),
            "timestamp":     now,
        },
    })

    if risk_level != "malicious":
        return  # nothing more to do for safe/suspicious nodes

    # -- Build alert document ----------------------
    alert = {
        "ip":            ip,
        "mac":           features.get("mac", "unknown"),
        "anomaly_score": anomaly_score,
        "risk_level":    risk_level,
        "packets_per_sec":     features.get("packets_per_sec", 0),
        "avg_packet_size":     features.get("avg_packet_size", 0),
        "unique_destinations": features.get("unique_destinations", 0),
        "timestamp":     now,
        "description":   f"Anomalous traffic detected from {ip} "
                         f"(score={anomaly_score})",
    }

    # -- Persist to MongoDB ------------------------
    await alerts_col().insert_one(dict(alert))

    # -- Push WebSocket alert ----------------------
    await ws_broadcast_fn({
        "event": "new_alert",
        "data":  alert,
    })

    # -- Write to log file -------------------------
    logging.warning(
        f"MALICIOUS | ip={ip} | score={anomaly_score} | "
        f"pps={features.get('packets_per_sec')} | "
        f"dests={features.get('unique_destinations')}"
    )

    print(f"[Alert] (MALICIOUS) node: {ip}  score={anomaly_score}")
