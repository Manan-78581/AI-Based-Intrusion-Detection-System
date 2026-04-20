# -------------------------------------------------
#  AI-IDS  -  MongoDB Client (async via Motor)
# -------------------------------------------------
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME   = os.getenv("DB_NAME",   "ai_ids")

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(MONGO_URI)
    return _client


def get_db():
    return get_client()[DB_NAME]


# -- Collection helpers ----------------------------
def nodes_col():
    return get_db()["nodes"]

def metrics_col():
    return get_db()["traffic_metrics"]

def alerts_col():
    return get_db()["alerts"]


# -- Startup / Shutdown ----------------------------
async def connect_db():
    get_client()
    print(f"[MongoDB] Connected -> {MONGO_URI} / {DB_NAME}")


async def close_db():
    global _client
    if _client:
        _client.close()
        _client = None
        print("[MongoDB] Connection closed")


async def clear_db():
    """Clear all collections and logs to start fresh."""
    db = get_db()
    await db["nodes"].drop()
    await db["traffic_metrics"].drop()
    await db["alerts"].drop()
    print("[MongoDB] Database cleared (all collections dropped)")

    # Also clear the log file if it exists
    log_path = "logs/alerts.log"
    if os.path.exists(log_path):
        try:
            with open(log_path, "w") as f:
                f.write("")
            print(f"[Logs] Cleared {log_path}")
        except Exception as e:
            print(f"[Logs] Could not clear log file: {e}")

    # Also clear the saved ML model to force re-training on new data
    model_path = "models/isolation_forest.pkl"
    if os.path.exists(model_path):
        try:
            os.remove(model_path)
            print(f"[Detector] Deleted old model: {model_path}")
        except Exception as e:
            print(f"[Detector] Could not delete model file: {e}")
