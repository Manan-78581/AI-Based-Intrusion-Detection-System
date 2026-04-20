// ─────────────────────────────────────────────────
//  AI-IDS  ·  useWebSocket hook
//  Connects to ws://localhost:8000/ws/live and
//  calls the provided callback on every message.
// ─────────────────────────────────────────────────
import { useEffect, useRef } from "react";
import type { WsEvent } from "../types";

const WS_URL = "ws://localhost:8000/ws/live";
const PING_INTERVAL = 20_000;

export function useWebSocket(onMessage: (evt: WsEvent) => void) {
    const wsRef = useRef<WebSocket | null>(null);
    const pingRef = useRef<ReturnType<typeof setInterval> | null>(null);

    useEffect(() => {
        function connect() {
            const ws = new WebSocket(WS_URL);
            wsRef.current = ws;

            ws.onopen = () => {
                console.log("[WS] Connected");
                pingRef.current = setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) ws.send("ping");
                }, PING_INTERVAL);
            };

            ws.onmessage = (e) => {
                try {
                    const data: WsEvent = JSON.parse(e.data);
                    onMessage(data);
                } catch {
                    // ignore non-JSON pong frames
                }
            };

            ws.onclose = () => {
                console.log("[WS] Disconnected — reconnecting in 3s");
                if (pingRef.current) clearInterval(pingRef.current);
                setTimeout(connect, 3000);
            };

            ws.onerror = () => ws.close();
        }

        connect();

        return () => {
            wsRef.current?.close();
            if (pingRef.current) clearInterval(pingRef.current);
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
}
