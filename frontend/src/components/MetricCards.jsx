import React from "react";
import { Activity, Gauge, Zap, AlertTriangle, Clock, Layers } from "lucide-react";

export function MetricCards({ metrics, stats }) {
  const cards = [
    {
      title: "LIVE INGESTION RATE",
      value: `${(metrics?.flows_per_sec || 0).toLocaleString()} flows/s`,
      sub: `${(metrics?.packets_per_sec || 0).toLocaleString()} pkts/s`,
      icon: Activity,
      color: "#06b6d4"
    },
    {
      title: "EFFECTIVE BANDWIDTH",
      value: `${(metrics?.mbps || 0).toFixed(2)} Mbps`,
      sub: "Read-only mirrored feed",
      icon: Gauge,
      color: "#3b82f6"
    },
    {
      title: "TOTAL FLOWS PROCESSED",
      value: (metrics?.total_processed_flows || 0).toLocaleString(),
      sub: `${metrics?.active_sources_count || 0} active sources`,
      icon: Layers,
      color: "#8b5cf6"
    },
    {
      title: "THREAT ALERTS RAISED",
      value: (stats?.total_threats || 0).toLocaleString(),
      sub: `${stats?.severity_breakdown?.CRITICAL || 0} Critical | ${stats?.severity_breakdown?.HIGH || 0} High`,
      icon: AlertTriangle,
      color: stats?.total_threats > 0 ? "#f43f5e" : "#10b981",
      pulse: stats?.total_threats > 0
    },
    {
      title: "AVG PIPELINE LATENCY",
      value: `${(metrics?.avg_processing_latency_ms || 0).toFixed(3)} ms`,
      sub: `P95: ${(metrics?.p95_processing_latency_ms || 0).toFixed(3)} ms | P99: ${(metrics?.p99_processing_latency_ms || 0).toFixed(3)} ms`,
      icon: Clock,
      color: "#10b981"
    }
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "14px", marginBottom: "20px" }}>
      {cards.map((card, idx) => {
        const IconComponent = card.icon;
        return (
          <div key={idx} className="glass-panel" style={{ padding: "16px", position: "relative", overflow: "hidden" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
              <span style={{ fontSize: "0.70rem", fontWeight: 700, letterSpacing: "0.05em", color: "var(--text-muted)" }}>
                {card.title}
              </span>
              <div style={{
                width: "28px",
                height: "28px",
                borderRadius: "6px",
                background: `rgba(${card.color === "#06b6d4" ? "6, 182, 212" : card.color === "#3b82f6" ? "59, 130, 246" : card.color === "#8b5cf6" ? "139, 92, 246" : card.color === "#f43f5e" ? "244, 63, 94" : "16, 185, 129"}, 0.12)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center"
              }}>
                <IconComponent size={16} color={card.color} />
              </div>
            </div>
            
            <div style={{ fontSize: "1.45rem", fontWeight: 700, color: "#f8fafc", marginBottom: "4px" }}>
              {card.value}
            </div>

            <div style={{ fontSize: "0.72rem", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "4px" }}>
              {card.sub}
            </div>

            {/* Subtle glow border at bottom */}
            <div style={{
              position: "absolute",
              bottom: 0,
              left: "10%",
              right: "10%",
              height: "2px",
              background: `linear-gradient(90deg, transparent, ${card.color}, transparent)`,
              opacity: 0.6
            }} />
          </div>
        );
      })}
    </div>
  );
}
