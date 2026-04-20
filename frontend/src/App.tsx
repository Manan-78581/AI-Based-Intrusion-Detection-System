import { useState, useCallback, useEffect } from "react";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import type { Node, Alert, WsEvent } from "./types";
import { useWebSocket } from "./hooks/useWebSocket";
import Overview from "./pages/Overview";
import Topology from "./pages/Topology";
import NodesTable from "./pages/NodesTable";
import AlertsPanel from "./pages/AlertsPanel";
import "./index.css";

// ── Icons (SVG inline) ────────────────────────────
const Icon = {
  overview: <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></svg>,
  topology: <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="12" cy="5" r="3" /><circle cx="5" cy="19" r="3" /><circle cx="19" cy="19" r="3" /><line x1="12" y1="8" x2="5" y2="16" /><line x1="12" y1="8" x2="19" y2="16" /></svg>,
  nodes: <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3" /><path d="M12 2v3m0 14v3M2 12h3m14 0h3m-3.3-6.7-2.1 2.1M7.4 16.6l-2.1 2.1m0-11.4 2.1 2.1m9.2 9.2 2.1 2.1" /></svg>,
  alerts: <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>,
};

function App() {
  const [nodes, setNodes] = useState<Record<string, Node>>({});
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [detectionEnabled, setDetectionEnabled] = useState(false);

  const handleWs = useCallback((evt: WsEvent) => {
    if (evt.event === "new_node" || evt.event === "traffic_update") {
      setNodes(prev => ({
        ...prev,
        [evt.data.ip]: { ...prev[evt.data.ip], ...evt.data },
      }));
    }
    if (evt.event === "new_alert") {
      setAlerts(prev => [evt.data, ...prev].slice(0, 200));
    }
    if (evt.event === "detection_status") {
      setDetectionEnabled(evt.data.detection_enabled);
    }
  }, []);

  useWebSocket(handleWs);

  // Fetch initial state
  useEffect(() => {
    // 1. Detection Status
    fetch('http://localhost:8000/detection/status')
      .then(r => r.json())
      .then(data => setDetectionEnabled(data.detection_enabled))
      .catch(() => {});

    // 2. Initial Nodes
    fetch('http://localhost:8000/nodes')
      .then(r => r.json())
      .then(data => {
        const nodeMap: Record<string, Node> = {};
        data.forEach((n: Node) => nodeMap[n.ip] = n);
        setNodes(nodeMap);
      })
      .catch(() => {});

    // 3. Initial Alerts
    fetch('http://localhost:8000/alerts')
      .then(r => r.json())
      .then(data => setAlerts(data))
      .catch(() => {});
  }, []);

  const nodeList = Object.values(nodes);

  return (
    <BrowserRouter>
      <div className="layout">

        {/* ── Sidebar ── */}
        <aside className="sidebar">
          <div className="sidebar-logo">
            <h1>🛡️ AI-IDS</h1>
            <span>Intrusion Detection System</span>
          </div>

          <nav className="sidebar-nav">
            <NavLink to="/" className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}>
              {Icon.overview} Overview
            </NavLink>
            <NavLink to="/topology" className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}>
              {Icon.topology} Network Topology
            </NavLink>
            <NavLink to="/nodes" className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}>
              {Icon.nodes} Nodes Table
            </NavLink>
            <NavLink to="/alerts" className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}>
              {Icon.alerts} Alerts Panel
              {alerts.length > 0 && (
                <span style={{
                  marginLeft: "auto",
                  background: "var(--malicious)",
                  color: "#fff",
                  borderRadius: "10px",
                  padding: "1px 7px",
                  fontSize: "11px",
                  fontWeight: 700,
                }}>
                  {alerts.length}
                </span>
              )}
            </NavLink>
          </nav>

          <div className="sidebar-footer">
            <div className="live-badge">
              <span className="live-dot" />
              LIVE MONITORING
            </div>
          </div>
        </aside>

        {/* ── Pages ── */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Overview nodes={nodeList} alerts={alerts} detectionEnabled={detectionEnabled} />} />
            <Route path="/topology" element={<Topology nodes={nodeList} />} />
            <Route path="/nodes" element={<NodesTable nodes={nodeList} />} />
            <Route path="/alerts" element={<AlertsPanel alerts={alerts} />} />
          </Routes>
        </main>

      </div>
    </BrowserRouter>
  );
}

export default App;
