import { useEffect, useState } from "react";
import {
    LineChart, Line, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend,
    BarChart, Bar,
} from "recharts";
import axios from "axios";
import type { Node, Alert, Stats } from "../types";

const API = "http://localhost:8000";

const PIE_COLORS = {
    safe: "#10b981",
    suspicious: "#f59e0b",
    malicious: "#ef4444",
};

interface Props {
    nodes: Node[];
    alerts: Alert[];
    detectionEnabled: boolean;
}

export default function Overview({ nodes, alerts, detectionEnabled }: Props) {
    const [stats, setStats] = useState<Stats | null>(null);
    const [detectionLoading, setDetectionLoading] = useState(false);

    useEffect(() => {
        axios.get<Stats>(`${API}/stats`)
            .then(r => setStats(r.data))
            .catch(() => { });
        const t = setInterval(() => {
            axios.get<Stats>(`${API}/stats`).then(r => setStats(r.data)).catch(() => { });
        }, 10_000);
        return () => clearInterval(t);
    }, []);

    const handleStartDetection = async () => {
        setDetectionLoading(true);
        try {
            await axios.post(`${API}/detection/start`);
            // Don't set state here - wait for WebSocket update
        } catch (error) {
            console.error('Failed to start detection:', error);
        } finally {
            setDetectionLoading(false);
        }
    };

    const handleStopDetection = async () => {
        setDetectionLoading(true);
        try {
            await axios.post(`${API}/detection/stop`);
            // Don't set state here - wait for WebSocket update
        } catch (error) {
            console.error('Failed to stop detection:', error);
        } finally {
            setDetectionLoading(false);
        }
    };

    const activeNodes = nodes.filter(n => n.status === "active").length || stats?.active_nodes || 0;
    const totalAlerts = alerts.length || stats?.total_alerts || 0;
    const maliciousN = nodes.filter(n => n.risk_level === "malicious").length;
    const suspiciousN = nodes.filter(n => n.risk_level === "suspicious").length;

    const pieData = [
        { name: "Safe", value: nodes.filter(n => n.risk_level === "safe").length || stats?.risk_distribution.safe || 0 },
        { name: "Suspicious", value: suspiciousN || stats?.risk_distribution.suspicious || 0 },
        { name: "Malicious", value: maliciousN || stats?.risk_distribution.malicious || 0 },
    ];

    const barData = [...nodes]
        .sort((a, b) => (b.anomaly_score ?? 0) - (a.anomaly_score ?? 0))
        .slice(0, 8)
        .map(n => ({
            ip: n.ip.split(".").at(-1) ? `...${n.ip.split(".").at(-1)}` : n.ip,
            score: n.anomaly_score ?? 0,
        }));

    const trendData = stats?.traffic_trend.map(t => ({
        time: new Date(t.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        pps: t.packets_per_sec,
    })) ?? [];

    return (
        <div>
            <div className="page-header">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <div>
                        <h2>System Overview</h2>
                        <p>Real-time network health and threat summary</p>
                    </div>
                    <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                        <div style={{ 
                            display: "flex", 
                            alignItems: "center", 
                            gap: 8, 
                            fontSize: 14, 
                            color: "var(--text-muted)" 
                        }}>
                            <span style={{ 
                                width: 12, 
                                height: 12, 
                                borderRadius: "50%", 
                                background: detectionEnabled ? "#10b981" : "#6b7280",
                                animation: detectionEnabled ? "pulse 2s infinite" : "none"
                            }} />
                            Detection: {detectionEnabled ? "Active" : "Inactive"}
                        </div>
                        {detectionEnabled ? (
                            <button
                                onClick={handleStopDetection}
                                disabled={detectionLoading}
                                style={{
                                    padding: "10px 20px",
                                    borderRadius: 8,
                                    border: "1px solid #ef4444",
                                    background: "#fee2e2",
                                    color: "#dc2626",
                                    cursor: detectionLoading ? "not-allowed" : "pointer",
                                    fontSize: 14,
                                    fontWeight: 600,
                                    transition: "all 0.2s",
                                }}
                            >
                                {detectionLoading ? "⏳ Stopping..." : "⏹️ Stop Detection"}
                            </button>
                        ) : (
                            <button
                                onClick={handleStartDetection}
                                disabled={detectionLoading}
                                style={{
                                    padding: "10px 20px",
                                    borderRadius: 8,
                                    border: "1px solid #10b981",
                                    background: "#d1fae5",
                                    color: "#059669",
                                    cursor: detectionLoading ? "not-allowed" : "pointer",
                                    fontSize: 14,
                                    fontWeight: 600,
                                    transition: "all 0.2s",
                                }}
                            >
                                {detectionLoading ? "⏳ Starting..." : "▶️ Start Detection"}
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* Stat Cards */}
            <div className="stat-grid">
                <div className="stat-card">
                    <div className="stat-icon" style={{ background: "rgba(59,130,246,0.15)" }}>🖥️</div>
                    <div className="stat-info">
                        <div className="value" style={{ color: "var(--accent-blue)" }}>{nodes.length || stats?.total_nodes || 0}</div>
                        <div className="label">Total Nodes</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon" style={{ background: "rgba(16,185,129,0.15)" }}>✅</div>
                    <div className="stat-info">
                        <div className="value" style={{ color: "var(--accent-green)" }}>{activeNodes}</div>
                        <div className="label">Active Nodes</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon" style={{ background: "rgba(245,158,11,0.15)" }}>⚠️</div>
                    <div className="stat-info">
                        <div className="value" style={{ color: "var(--accent-yellow)" }}>{suspiciousN}</div>
                        <div className="label">Suspicious Nodes</div>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="stat-icon" style={{ background: "rgba(239,68,68,0.15)" }}>🚨</div>
                    <div className="stat-info">
                        <div className="value" style={{ color: "var(--accent-red)" }}>{totalAlerts}</div>
                        <div className="label">Total Alerts</div>
                    </div>
                </div>
            </div>

            {/* Charts Row */}
            <div className="charts-grid">
                {/* Line Chart */}
                <div className="card">
                    <div className="card-title">Traffic Over Time (packets/sec)</div>
                    {trendData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={220}>
                            <LineChart data={trendData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 11 }} />
                                <YAxis stroke="#475569" tick={{ fontSize: 11 }} />
                                <Tooltip
                                    contentStyle={{ background: "#0f1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }}
                                    labelStyle={{ color: "#94a3b8" }}
                                />
                                <Line type="monotone" dataKey="pps" stroke="#3b82f6" strokeWidth={2} dot={false} name="Packets/s" />
                            </LineChart>
                        </ResponsiveContainer>
                    ) : (
                        <div style={{ height: 220, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                            Waiting for traffic data…
                        </div>
                    )}
                </div>

                {/* Pie Chart */}
                <div className="card">
                    <div className="card-title">Threat Distribution</div>
                    <ResponsiveContainer width="100%" height={220}>
                        <PieChart>
                            <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                                dataKey="value" paddingAngle={4}>
                                {pieData.map((entry) => (
                                    <Cell key={entry.name} fill={PIE_COLORS[entry.name.toLowerCase() as keyof typeof PIE_COLORS]} />
                                ))}
                            </Pie>
                            <Tooltip contentStyle={{ background: "#0f1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                            <Legend wrapperStyle={{ fontSize: 12 }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Bar Chart */}
            {barData.length > 0 && (
                <div className="card" style={{ marginBottom: 28 }}>
                    <div className="card-title">Top Risky Nodes (Anomaly Score)</div>
                    <ResponsiveContainer width="100%" height={180}>
                        <BarChart data={barData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                            <XAxis dataKey="ip" stroke="#475569" tick={{ fontSize: 11 }} />
                            <YAxis domain={[0, 1]} stroke="#475569" tick={{ fontSize: 11 }} />
                            <Tooltip contentStyle={{ background: "#0f1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                            <Bar dataKey="score" name="Anomaly Score" radius={[4, 4, 0, 0]}>
                                {barData.map((d) => (
                                    <Cell key={d.ip} fill={d.score > 0.7 ? "#ef4444" : d.score > 0.4 ? "#f59e0b" : "#10b981"} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            )}

            {/* Recent Alerts */}
            {alerts.length > 0 && (
                <div className="card">
                    <div className="card-title">Recent Alerts</div>
                    <div className="alert-feed">
                        {alerts.slice(0, 5).map((a, i) => (
                            <div className="alert-item" key={i}>
                                <span className="alert-icon">🚨</span>
                                <div className="alert-info">
                                    <div className="ip">{a.ip}</div>
                                    <div className="desc">{a.description}</div>
                                </div>
                                <div className="alert-meta">
                                    <div className="score">{(a.anomaly_score * 100).toFixed(0)}%</div>
                                    <div className="time">{new Date(a.timestamp).toLocaleTimeString()}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
