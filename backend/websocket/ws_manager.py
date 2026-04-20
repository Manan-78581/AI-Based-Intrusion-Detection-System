# ─────────────────────────────────────────────────
#  AI-IDS  ·  WebSocket Connection Manager
#  Manages all active WebSocket connections and
#  broadcasts JSON events to every connected client.
# ─────────────────────────────────────────────────
import json
import asyncio
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.active.append(ws)
        print(f"[WS] Client connected  · total={len(self.active)}")

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self.active = [c for c in self.active if c is not ws]
        print(f"[WS] Client disconnected · total={len(self.active)}")

    async def broadcast(self, payload: dict):
        """Send JSON payload to every connected client."""
        message = json.dumps(payload)
        dead: list[WebSocket] = []

        async with self._lock:
            targets = list(self.active)

        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        # Clean up broken connections
        for ws in dead:
            await self.disconnect(ws)


# ── Singleton used across the whole app ──────────
manager = ConnectionManager()


async def broadcast(payload: dict):
    """Module-level shortcut for the scanner / alert engine."""
    await manager.broadcast(payload)
