// ─────────────────────────────────────────────────
//  AI-IDS  ·  Shared TypeScript Types
// ─────────────────────────────────────────────────

export interface Node {
    ip: string;
    mac: string;
    status: "active" | "inactive";
    risk_level: "safe" | "suspicious" | "malicious";
    anomaly_score?: number;
    packets_per_sec?: number;
    avg_packet_size?: number;
    unique_destinations?: number;
    first_seen?: string;
    last_seen?: string;
    latest_metrics?: TrafficMetric;
}

export interface TrafficMetric {
    ip: string;
    packets_per_sec: number;
    avg_packet_size: number;
    unique_destinations: number;
    tcp_ratio: number;
    udp_ratio: number;
    connection_count: number;
    timestamp: string;
}

export interface Alert {
    ip: string;
    mac?: string;
    anomaly_score: number;
    risk_level: "malicious" | "suspicious";
    packets_per_sec?: number;
    avg_packet_size?: number;
    unique_destinations?: number;
    timestamp: string;
    description: string;
}

export interface Stats {
    total_nodes: number;
    active_nodes: number;
    total_alerts: number;
    risk_distribution: {
        malicious: number;
        suspicious: number;
        safe: number;
    };
    traffic_trend: Array<{
        ip: string;
        packets_per_sec: number;
        timestamp: string;
    }>;
}

// WebSocket event
export type WsEvent =
    | { event: "new_node"; data: Node }
    | { event: "traffic_update"; data: Node & { timestamp: string } }
    | { event: "new_alert"; data: Alert }
    | { event: "topology_update"; data: unknown }
    | { event: "detection_status"; data: { detection_enabled: boolean } };
