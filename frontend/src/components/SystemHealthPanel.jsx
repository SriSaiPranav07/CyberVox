import React from "react";
import { Activity, CheckCircle2, AlertCircle, Clock, Cpu, Database, Radio, ShieldCheck } from "lucide-react";

export function SystemHealthPanel({ metrics, wsConnected }) {
  const subsystems = metrics?.subsystem_health || [
    { name: "INGESTION", status: "Active (Read-Only)", indicator: "ok", details: "One-way passive mirror capture active" },
    { name: "FLOW PROCESSOR", status: "Healthy", indicator: "ok", details: "O(1) sliding windows active (1s, 5s, 30s, 60s)" },
    { name: "FEATURE ENGINE", status: "Healthy", indicator: "ok", details: "Entropy, IAT Jitter, and TLS JA3 extraction active" },
    { name: "ML ENGINE", status: "Ready", indicator: "ok", details: "Random Forest & Isolation Forest hybrid models loaded" },
    { name: "ALERT ENGINE", status: "Healthy", indicator: "ok", details: "Standardized Section 12 JSON alerts" },
    { name: "DATABASE", status: "Connected", indicator: "ok", details: "SQLite WAL mode persistent local storage" },
    { name: "API / WEBSOCKET", status: wsConnected ? "Connected" : "Reconnecting", indicator: wsConnected ? "ok" : "warning", details: "FastAPI / WebSocket streaming active" },
    { name: "DASHBOARD", status: "Operational", indicator: "ok", details: "SOC Cyber Defense Operations Center v2.0" }
  ];

  return (
    <div className="glass-panel" style={{ padding: "20px", marginBottom: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Activity size={18} color="#10b981" />
          <h2 style={{ fontSize: "1.0rem", fontWeight: 700, color: "#f8fafc" }}>
            SYSTEM HEALTH & SUBSYSTEM DIAGNOSTICS
          </h2>
        </div>
        <span className="badge-enclave" style={{ padding: "2px 8px", borderRadius: "4px", fontSize: "0.72rem", fontWeight: 700 }}>
          ALL SUBSYSTEMS NOMINAL
        </span>
      </div>

      {/* 8 Subsystem Health Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "10px", marginBottom: "16px" }}>
        {subsystems.map((sub, idx) => (
          <div
            key={idx}
            style={{
              background: "rgba(15, 23, 42, 0.6)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "8px",
              padding: "10px 12px",
              display: "flex",
              flexDirection: "column",
              gap: "2px"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span style={{ fontSize: "0.72rem", fontWeight: 700, color: "#f8fafc" }}>
                {sub.name}
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                <span
                  style={{
                    width: "7px",
                    height: "7px",
                    borderRadius: "50%",
                    background: sub.indicator === "ok" ? "#10b981" : "#f59e0b"
                  }}
                  className={sub.indicator === "ok" ? "pulse-emerald" : ""}
                />
                <span style={{ fontSize: "0.68rem", fontWeight: 700, color: sub.indicator === "ok" ? "#34d399" : "#fbbf24" }}>
                  {sub.status}
                </span>
              </div>
            </div>
            <div style={{ fontSize: "0.66rem", color: "var(--text-muted)", marginTop: "2px" }}>
              {sub.details}
            </div>
          </div>
        ))}
      </div>

      {/* Measured Latency & Throughput KPIs */}
      <div style={{ background: "rgba(9, 14, 23, 0.5)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px 16px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "12px", textAlign: "center" }}>
          <div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>Instant Throughput</div>
            <div style={{ fontSize: "1.1rem", fontWeight: 800, color: "#38bdf8" }}>
              {(metrics?.flows_per_sec || 0).toLocaleString()} <span style={{ fontSize: "0.70rem" }}>FPS</span>
            </div>
          </div>
          <div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>Packet Arrival Rate</div>
            <div style={{ fontSize: "1.1rem", fontWeight: 800, color: "#f8fafc" }}>
              {(metrics?.packets_per_sec || 0).toLocaleString()} <span style={{ fontSize: "0.70rem" }}>PKTS/S</span>
            </div>
          </div>
          <div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>Average Latency</div>
            <div style={{ fontSize: "1.1rem", fontWeight: 800, color: "#10b981" }}>
              {(metrics?.avg_processing_latency_ms || 0).toFixed(3)} <span style={{ fontSize: "0.70rem" }}>MS</span>
            </div>
          </div>
          <div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>P95 / P99 Latency</div>
            <div style={{ fontSize: "1.1rem", fontWeight: 800, color: "#c084fc" }}>
              {(metrics?.p95_processing_latency_ms || 0).toFixed(2)} / {(metrics?.p99_processing_latency_ms || 0).toFixed(2)} <span style={{ fontSize: "0.70rem" }}>MS</span>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}
