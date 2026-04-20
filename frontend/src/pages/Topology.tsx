import { useEffect, useRef, useMemo } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { ForceGraphMethods, NodeObject } from "react-force-graph-2d";
import type { Node } from "../types";

interface Props { nodes: Node[]; }

type FGNode = { id: string; mac: string; risk: string; status: string; isRouter?: boolean };
type FGLink = { source: string; target: string };

const RISK_COLOR: Record<string, string> = {
    safe: "#10b981",
    suspicious: "#f59e0b",
    malicious: "#ef4444",
};

export default function Topology({ nodes }: Props) {
    const fgRef = useRef<ForceGraphMethods<NodeObject<FGNode>> | undefined>(undefined);

    const { graphData } = useMemo(() => {
        const routerNode: FGNode = {
            id: "Router",
            mac: "Gateway",
            risk: "safe",
            status: "active",
            isRouter: true,
        };

        const deviceNodes: FGNode[] = nodes.map(n => ({
            id: n.ip,
            mac: n.mac,
            risk: n.risk_level,
            status: n.status,
        }));

        const links: FGLink[] = deviceNodes.map(n => ({
            source: "Router",
            target: n.id,
        }));

        return { graphData: { nodes: [routerNode, ...deviceNodes], links } };
    }, [nodes]);

    useEffect(() => {
        if (fgRef.current) {
            fgRef.current.d3Force("charge")?.strength(-200);
        }
    }, []);

    return (
        <div>
            <div className="page-header">
                <h2>Network Topology</h2>
                <p>Live force-directed graph of all discovered devices</p>
            </div>

            {/* Legend */}
            <div style={{ display: "flex", gap: 20, marginBottom: 16, flexWrap: "wrap" }}>
                {[
                    { label: "Safe", color: "#10b981" },
                    { label: "Suspicious", color: "#f59e0b" },
                    { label: "Malicious", color: "#ef4444" },
                    { label: "Router", color: "#3b82f6" },
                ].map(l => (
                    <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "#94a3b8" }}>
                        <span style={{ width: 12, height: 12, borderRadius: "50%", background: l.color, display: "inline-block" }} />
                        {l.label}
                    </div>
                ))}
            </div>

            <div className="topology-wrapper">
                {nodes.length === 0 ? (
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", fontSize: 14 }}>
                        ⏳ Waiting for nodes to be discovered by the ARP scanner…
                    </div>
                ) : (
                    <ForceGraph2D
                        ref={fgRef}
                        graphData={graphData}
                        backgroundColor="#0a0e1a"
                        nodeLabel={(n: FGNode) =>
                            n.isRouter
                                ? "🌐 Router / Gateway"
                                : `IP: ${n.id}\nMAC: ${n.mac}\nRisk: ${n.risk}`
                        }
                        nodeCanvasObject={(node, ctx, globalScale) => {
                            const n = node as FGNode & { x?: number; y?: number };
                            const x = n.x ?? 0;
                            const y = n.y ?? 0;
                            const r = n.isRouter ? 16 : 10;
                            const color = n.isRouter ? "#3b82f6" : (RISK_COLOR[n.risk] ?? "#10b981");

                            // Glow
                            ctx.shadowColor = color;
                            ctx.shadowBlur = 15;

                            ctx.beginPath();
                            ctx.arc(x, y, r, 0, 2 * Math.PI);
                            ctx.fillStyle = color + "cc";
                            ctx.fill();
                            ctx.strokeStyle = color;
                            ctx.lineWidth = 2;
                            ctx.stroke();

                            ctx.shadowBlur = 0;

                            // Label
                            const label = n.isRouter ? "Router" : n.id.split(".").at(-1) ?? n.id;
                            const fontSize = 10 / globalScale;
                            ctx.font = `600 ${fontSize}px Inter, sans-serif`;
                            ctx.fillStyle = "#f1f5f9";
                            ctx.textAlign = "center";
                            ctx.fillText(label, x, y + r + fontSize + 2);
                        }}
                        linkColor={() => "rgba(59,130,246,0.25)"}
                        linkWidth={1.5}
                        linkDirectionalParticles={2}
                        linkDirectionalParticleWidth={2}
                        linkDirectionalParticleColor={() => "rgba(59,130,246,0.6)"}
                        cooldownTicks={80}
                        width={window.innerWidth - 290}
                        height={550}
                    />
                )}
            </div>
        </div>
    );
}
