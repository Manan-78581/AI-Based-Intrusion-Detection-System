# ─────────────────────────────────────────────────
#  AI-IDS  ·  FastAPI REST Routes
#  Exposes all REST endpoints consumed by the
#  React dashboard.
# ─────────────────────────────────────────────────
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from database.mongo_client import nodes_col, metrics_col, alerts_col

from backend.state import state

router = APIRouter()


def _strip_id(doc: dict) -> dict:
    """Remove MongoDB ObjectId before JSON serialisation."""
    doc.pop("_id", None)
    return doc


# ── GET /nodes ────────────────────────────────────
@router.get("/nodes")
async def get_nodes():
    """Return all known network nodes."""
    docs = await nodes_col().find().to_list(length=200)
    return [_strip_id(d) for d in docs]


# ── GET /node/{ip} ────────────────────────────────
@router.get("/node/{ip:path}")
async def get_node(ip: str):
    """Return detailed telemetry for a single node."""
    node = await nodes_col().find_one({"ip": ip})
    if not node:
        return JSONResponse({"error": "Node not found"}, status_code=404)

    # Attach latest traffic metrics
    metrics = await metrics_col().find_one(
        {"ip": ip}, sort=[("timestamp", -1)]
    )
    node_data = _strip_id(node)
    if metrics:
        node_data["latest_metrics"] = _strip_id(metrics)

    return node_data


# ── GET /alerts ───────────────────────────────────
@router.get("/alerts")
async def get_alerts(limit: int = 100):
    """Return the most recent alerts (newest first)."""
    docs = await (
        alerts_col()
        .find()
        .sort("timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )
    return [_strip_id(d) for d in docs]


# ── GET /stats ────────────────────────────────────
@router.get("/stats")
async def get_stats():
    """Aggregate statistics for dashboard cards and graphs."""
    total_nodes   = await nodes_col().count_documents({})
    active_nodes  = await nodes_col().count_documents({"status": "active"})
    total_alerts  = await alerts_col().count_documents({})
    malicious     = await nodes_col().count_documents({"risk_level": "malicious"})
    suspicious    = await nodes_col().count_documents({"risk_level": "suspicious"})
    safe          = await nodes_col().count_documents({"risk_level": "safe"})

    # Last 50 traffic_metrics rows for line chart
    trend = await (
        metrics_col()
        .find({}, {"_id": 0, "ip": 1, "packets_per_sec": 1, "timestamp": 1})
        .sort("timestamp", -1)
        .limit(50)
        .to_list(length=50)
    )

    return {
        "total_nodes":  total_nodes,
        "active_nodes": active_nodes,
        "total_alerts": total_alerts,
        "risk_distribution": {
            "malicious":  malicious,
            "suspicious": suspicious,
            "safe":       safe,
        },
        "traffic_trend": list(reversed(trend)),
    }


# ── Detection Control Endpoints ───────────────────

@router.get("/detection/status")
async def get_detection_status():
    """Return current detection status."""
    return {"detection_enabled": state.detection_enabled}


@router.post("/detection/start")
async def start_detection():
    """Start network device detection."""
    state.detection_enabled = True
    
    # Broadcast status change
    from backend.websocket.ws_manager import broadcast
    await broadcast({
        "event": "detection_status",
        "data": {"detection_enabled": True}
    })
    
    return {"message": "Network detection started", "detection_enabled": True}


@router.post("/detection/stop")
async def stop_detection():
    """Stop network device detection."""
    state.detection_enabled = False
    
    # Broadcast status change
    from backend.websocket.ws_manager import broadcast
    await broadcast({
        "event": "detection_status",
        "data": {"detection_enabled": False}
    })
    
    return {"message": "Network detection stopped", "detection_enabled": False}
