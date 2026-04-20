# -------------------------------------------------
#  AI-IDS  -  Backend Entry Point (main.py)
#  Run with:  python main.py
#             (admin needed for raw packet capture)
# -------------------------------------------------
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from database.mongo_client import connect_db, close_db, clear_db
from backend.scanner.arp_scanner import run_scanner
from backend.sniffer.packet_capture import start_sniffer
from backend.features.aggregator import run_aggregator
from backend.ml.detector import detector
from backend.alerts.alert_engine import process_detection
from backend.api.routes import router
from backend.websocket.ws_manager import manager, broadcast


# -- ML pipeline: aggregator -> detector -> alert ---
async def on_features_ready(features: dict):
    score, risk = detector.score(features)
    await process_detection(features, score, risk, broadcast)


# -- App Lifecycle ---------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup -----------------------------------
    await connect_db()
    await clear_db()                                    # start fresh on every run
    detector.reset()                                    # clear ML state
    start_sniffer()                                     # background thread
    asyncio.create_task(run_scanner(broadcast))         # ARP scan loop
    asyncio.create_task(run_aggregator(on_features_ready))  # feature loop
    print("[Main] (OK) AI-IDS backend is running")

    yield  # app is live

    # -- Shutdown ----------------------------------
    await close_db()
    print("[Main] (STOP) Shutdown complete")


# -- FastAPI App -----------------------------------
app = FastAPI(
    title="AI-IDS API",
    description="AI-Based Network Intrusion Detection System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- REST routes -----------------------------------
app.include_router(router)


# -- WebSocket endpoint ----------------------------
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; client sends pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


# -- Dev entry point -------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
