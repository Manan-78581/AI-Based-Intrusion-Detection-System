import { useEffect, useState, useMemo } from "react";
import axios from "axios";
import type { Node } from "../types";

const API = "http://localhost:8000";

interface Props { nodes: Node[]; }

type SortKey = keyof Node;

export default function NodesTable({ nodes: liveNodes }: Props) {
    const [fetched, setFetched] = useState<Node[]>([]);
    const [search, setSearch] = useState("");
    const [filter, setFilter] = useState<"all" | "safe" | "suspicious" | "malicious">("all");
    const [sortKey, setSortKey] = useState<SortKey>("ip");
    const [sortAsc, setSortAsc] = useState(true);

    useEffect(() => {
        axios.get<Node[]>(`${API}/nodes`).then(r => setFetched(r.data)).catch(() => { });
        const t = setInterval(() => {
            axios.get<Node[]>(`${API}/nodes`).then(r => setFetched(r.data)).catch(() => { });
        }, 10_000);
        return () => clearInterval(t);
    }, []);

    // Merge REST data with live WebSocket updates
    const merged = useMemo(() => {
        const map: Record<string, Node> = {};
        fetched.forEach(n => { map[n.ip] = n; });
        liveNodes.forEach(n => { map[n.ip] = { ...map[n.ip], ...n }; });
        return Object.values(map);
    }, [fetched, liveNodes]);

    const displayed = useMemo(() => {
        let list = merged;
        if (filter !== "all") list = list.filter(n => n.risk_level === filter);
        if (search) {
            const q = search.toLowerCase();
            list = list.filter(n => n.ip.includes(q) || n.mac.toLowerCase().includes(q));
        }
        list = [...list].sort((a, b) => {
            const av = a[sortKey] ?? "";
            const bv = b[sortKey] ?? "";
            return sortAsc
                ? String(av).localeCompare(String(bv), undefined, { numeric: true })
                : String(bv).localeCompare(String(av), undefined, { numeric: true });
        });
        return list;
    }, [merged, search, filter, sortKey, sortAsc]);

    function handleSort(key: SortKey) {
        if (sortKey === key) setSortAsc(p => !p);
        else { setSortKey(key); setSortAsc(true); }
    }

    function arrow(key: SortKey) {
        if (sortKey !== key) return " ⇅";
        return sortAsc ? " ▲" : " ▼";
    }

    return (
        <div>
            <div className="page-header">
                <h2>Nodes Table</h2>
                <p>{displayed.length} of {merged.length} nodes shown</p>
            </div>

            {/* Controls */}
            <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
                <div className="search-bar" style={{ marginBottom: 0 }}>
                    <span style={{ color: "var(--text-muted)" }}>🔍</span>
                    <input
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        placeholder="Search by IP or MAC…"
                    />
                </div>

                {(["all", "safe", "suspicious", "malicious"] as const).map(f => (
                    <button
                        key={f}
                        onClick={() => setFilter(f)}
                        style={{
                            padding: "9px 16px",
                            borderRadius: 8,
                            border: "1px solid",
                            cursor: "pointer",
                            fontSize: 13,
                            fontWeight: 600,
                            fontFamily: "Inter, sans-serif",
                            textTransform: "capitalize",
                            transition: "all 0.2s",
                            borderColor: filter === f
                                ? (f === "all" ? "var(--accent-blue)" : `var(--${f === "safe" ? "safe" : f === "suspicious" ? "suspicious" : "malicious"})`)
                                : "var(--border)",
                            background: filter === f ? "rgba(59,130,246,0.1)" : "transparent",
                            color: filter === f ? "var(--text-primary)" : "var(--text-secondary)",
                        }}
                    >
                        {f}
                    </button>
                ))}
            </div>

            <div className="card" style={{ padding: 0, overflow: "hidden" }}>
                <div className="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                {([
                                    ["ip", "IP Address"],
                                    ["mac", "MAC Address"],
                                    ["status", "Status"],
                                    ["packets_per_sec", "Pkts / s"],
                                    ["anomaly_score", "Anomaly Score"],
                                    ["risk_level", "Risk Level"],
                                    ["last_seen", "Last Seen"],
                                ] as [SortKey, string][]).map(([key, label]) => (
                                    <th key={key} onClick={() => handleSort(key)}>
                                        {label}{arrow(key)}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {displayed.length === 0 ? (
                                <tr>
                                    <td colSpan={7} style={{ textAlign: "center", color: "var(--text-muted)", padding: "40px 0" }}>
                                        No nodes found
                                    </td>
                                </tr>
                            ) : displayed.map(n => (
                                <tr key={n.ip}>
                                    <td style={{ color: "var(--accent-cyan)" }}>{n.ip}</td>
                                    <td style={{ color: "var(--text-secondary)" }}>{n.mac}</td>
                                    <td>
                                        <span style={{
                                            display: "inline-flex", alignItems: "center", gap: 6,
                                            color: n.status === "active" ? "var(--safe)" : "var(--text-muted)",
                                            fontSize: 12, fontWeight: 600,
                                        }}>
                                            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "currentColor" }} />
                                            {n.status}
                                        </span>
                                    </td>
                                    <td>{n.packets_per_sec?.toFixed(1) ?? "—"}</td>
                                    <td>
                                        {n.anomaly_score !== undefined ? (
                                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                                <div style={{
                                                    height: 5, width: 80, background: "var(--border)",
                                                    borderRadius: 3, overflow: "hidden",
                                                }}>
                                                    <div style={{
                                                        height: "100%",
                                                        width: `${(n.anomaly_score ?? 0) * 100}%`,
                                                        background: n.anomaly_score > 0.7 ? "var(--malicious)"
                                                            : n.anomaly_score > 0.4 ? "var(--suspicious)"
                                                                : "var(--safe)",
                                                        borderRadius: 3,
                                                    }} />
                                                </div>
                                                {(n.anomaly_score * 100).toFixed(0)}%
                                            </div>
                                        ) : "—"}
                                    </td>
                                    <td>
                                        <span className={`risk-badge ${n.risk_level}`}>
                                            <span className="dot" />
                                            {n.risk_level}
                                        </span>
                                    </td>
                                    <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                                        {n.last_seen ? new Date(n.last_seen).toLocaleTimeString() : "—"}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
