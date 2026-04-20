import { useEffect, useState } from "react";
import axios from "axios";
import type { Alert } from "../types";

const API = "http://localhost:8000";

interface Props { alerts: Alert[]; }

export default function AlertsPanel({ alerts: liveAlerts }: Props) {
    const [fetched, setFetched] = useState<Alert[]>([]);
    const [filter, setFilter] = useState<"all" | "malicious" | "suspicious">("all");

    useEffect(() => {
        axios.get<Alert[]>(`${API}/alerts`).then(r => setFetched(r.data)).catch(() => { });
        const t = setInterval(() => {
            axios.get<Alert[]>(`${API}/alerts`).then(r => setFetched(r.data)).catch(() => { });
        }, 15_000);
        return () => clearInterval(t);
    }, []);

    // Merge: live state (newest) + REST historical
    const seenIps = new Set(liveAlerts.map(a => a.timestamp + a.ip));
    const merged = [
        ...liveAlerts,
        ...fetched.filter(a => !seenIps.has(a.timestamp + a.ip)),
    ];

    const displayed = filter === "all" ? merged : merged.filter(a => a.risk_level === filter);

    function scoreColor(s: number) {
        if (s > 0.7) return "var(--malicious)";
        if (s > 0.4) return "var(--suspicious)";
        return "var(--safe)";
    }

    return (
        <div>
            <div className="page-header">
                <h2>Alerts Panel</h2>
                <p>{displayed.length} alert{displayed.length !== 1 ? "s" : ""} — real-time feed</p>
            </div>

            {/* Filter */}
            <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
                {(["all", "malicious", "suspicious"] as const).map(f => (
                    <button
                        key={f}
                        onClick={() => setFilter(f)}
                        style={{
                            padding: "8px 18px",
                            borderRadius: 8,
                            border: "1px solid",
                            cursor: "pointer",
                            fontSize: 13,
                            fontWeight: 600,
                            fontFamily: "Inter, sans-serif",
                            textTransform: "capitalize",
                            transition: "all 0.2s",
                            borderColor: filter === f
                                ? (f === "all" ? "var(--accent-blue)" : f === "malicious" ? "var(--malicious)" : "var(--suspicious)")
                                : "var(--border)",
                            background: filter === f ? "rgba(239,68,68,0.1)" : "transparent",
                            color: filter === f ? "var(--text-primary)" : "var(--text-secondary)",
                        }}
                    >
                        {f}
                    </button>
                ))}
            </div>

            {displayed.length === 0 ? (
                <div className="card" style={{ textAlign: "center", padding: "60px 0", color: "var(--text-muted)" }}>
                    <div style={{ fontSize: 40, marginBottom: 12 }}>✅</div>
                    <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 6, color: "var(--text-secondary)" }}>
                        No alerts detected
                    </div>
                    <div style={{ fontSize: 13 }}>All monitored nodes are behaving normally</div>
                </div>
            ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {displayed.map((a, i) => (
                        <div
                            key={i}
                            style={{
                                background: a.risk_level === "malicious"
                                    ? "rgba(239,68,68,0.07)"
                                    : "rgba(245,158,11,0.07)",
                                border: `1px solid ${a.risk_level === "malicious"
                                    ? "rgba(239,68,68,0.25)"
                                    : "rgba(245,158,11,0.25)"}`,
                                borderRadius: 12,
                                padding: "16px 20px",
                                display: "grid",
                                gridTemplateColumns: "auto 1fr auto",
                                gap: 16,
                                alignItems: "center",
                                animation: "slideIn 0.35s ease",
                            }}
                        >
                            {/* Icon */}
                            <span style={{ fontSize: 22 }}>
                                {a.risk_level === "malicious" ? "🔴" : "🟡"}
                            </span>

                            {/* Info */}
                            <div>
                                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4, flexWrap: "wrap" }}>
                                    <span style={{
                                        fontFamily: "JetBrains Mono, monospace",
                                        fontWeight: 700,
                                        fontSize: 15,
                                        color: scoreColor(a.anomaly_score),
                                    }}>
                                        {a.ip}
                                    </span>
                                    <span className={`risk-badge ${a.risk_level}`}>
                                        <span className="dot" />
                                        {a.risk_level}
                                    </span>
                                    {a.mac && (
                                        <span style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "JetBrains Mono, monospace" }}>
                                            {a.mac}
                                        </span>
                                    )}
                                </div>
                                <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>{a.description}</div>
                                <div style={{ display: "flex", gap: 20, marginTop: 8, flexWrap: "wrap" }}>
                                    {a.packets_per_sec !== undefined && (
                                        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                                            📦 <strong style={{ color: "var(--text-secondary)" }}>{a.packets_per_sec.toFixed(1)}</strong> pkts/s
                                        </span>
                                    )}
                                    {a.avg_packet_size !== undefined && (
                                        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                                            📏 <strong style={{ color: "var(--text-secondary)" }}>{a.avg_packet_size.toFixed(0)}</strong> B avg
                                        </span>
                                    )}
                                    {a.unique_destinations !== undefined && (
                                        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                                            🎯 <strong style={{ color: "var(--text-secondary)" }}>{a.unique_destinations}</strong> destinations
                                        </span>
                                    )}
                                </div>
                            </div>

                            {/* Score + time */}
                            <div style={{ textAlign: "right", flexShrink: 0 }}>
                                <div style={{
                                    fontFamily: "JetBrains Mono, monospace",
                                    fontWeight: 800,
                                    fontSize: 20,
                                    color: scoreColor(a.anomaly_score),
                                }}>
                                    {(a.anomaly_score * 100).toFixed(0)}%
                                </div>
                                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                                    {new Date(a.timestamp).toLocaleDateString()} {new Date(a.timestamp).toLocaleTimeString()}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
