# 🛡️ AI-IDS — AI-Based Network Intrusion Detection System

> College Major Project · Python + React + TypeScript + MongoDB

---

## 📁 Project Structure

```
major proejct/         ← ROOT of project
├── main.py            ← FastAPI entry point (run with sudo)
├── requirements.txt   ← Python dependencies
├── .env               ← MongoDB URI config
│
├── backend/
│   ├── scanner/       ← ARP network discovery
│   ├── sniffer/       ← Live packet capture (Scapy)
│   ├── features/      ← Feature aggregation (per-node)
│   ├── ml/            ← Isolation Forest anomaly detection
│   ├── alerts/        ← Alert engine (MongoDB + WebSocket + log)
│   ├── api/           ← FastAPI REST routes
│   └── websocket/     ← WebSocket connection manager
│
├── database/          ← MongoDB async client (Motor)
├── models/            ← Saved ML model (.pkl)
├── logs/              ← alerts.log file
├── docs/              ← Project planning document
│
└── frontend/          ← React + TypeScript dashboard
    └── src/
        ├── pages/     ← Overview | Topology | Nodes | Alerts
        ├── hooks/     ← useWebSocket
        └── types/     ← Shared TypeScript interfaces
```

---

## 🚀 Quick Start

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Start MongoDB
```bash
# Make sure MongoDB is running on localhost:27017
mongod
```

### 3. Start the backend (needs admin/sudo for packet capture)
```bash
# Linux / Mac
sudo python main.py

# Windows — run terminal as Administrator
python main.py
```
Backend is now running at `http://localhost:8000`

### 4. Start the frontend
```bash
cd frontend
npm install
npm run dev
```
Dashboard is now at `http://localhost:5173`

---

## 🌐 API Endpoints

| Method | Endpoint         | Description                  |
|--------|------------------|------------------------------|
| GET    | `/nodes`         | All discovered nodes         |
| GET    | `/node/{ip}`     | Single node + telemetry      |
| GET    | `/alerts`        | All alerts history           |
| GET    | `/stats`         | Dashboard stats + trends     |
| WS     | `/ws/live`       | Real-time WebSocket channel  |

---

## 🧠 ML Model

- **Algorithm**: Isolation Forest (scikit-learn)
- **Anomaly Score**: 0.0 (normal) → 1.0 (anomalous)
- **Risk Levels**: `safe` < 0.4 | `suspicious` 0.4–0.7 | `malicious` > 0.7
- **Model file**: `models/isolation_forest.pkl` (auto-saved after 20+ samples)

---

## Made By
Manan kathuria 
simran Lakha
Meeta
