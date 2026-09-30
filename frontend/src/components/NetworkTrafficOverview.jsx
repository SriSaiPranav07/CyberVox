import React from "react";
import { Activity, Gauge, Layers, Hash, Network, ArrowDownRight, ArrowUpRight } from "lucide-react";

export function NetworkTrafficOverview({ metrics }) {
  const topSources = metrics?.top_sources || [];
  const topDestinations = metrics?.top_destinations || [];
  const topPorts = metrics?.top_ports || [];

  return (
    <div className="glass-panel" style={{ padding: "18px 20px", marginBottom: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "14px" }}>
        <div>
          <h2 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc" }}>
            NETWORK TRAFFIC ANALYTICS & ENTITY OVERVIEW
          </h2>
          <p style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
            Observed telemetry, packet distributions, and top active communication endpoints
          </p>
        </div>
        <div style={{ display: "flex", gap: "12px", fontSize: "0.74rem" }}>
          <span style={{ color: "var(--text-secondary)" }}>
            Total Packets: <strong style={{ color: "#38bdf8" }}>{(metrics?.total_processed_packets || 0).toLocaleString()}</strong>
          </span>
          <span style={{ color: "var(--border-subtle)" }}>|</span>
          <span style={{ color: "var(--text-secondary)" }}>
            Total Volume: <strong style={{ color: "#10b981" }}>{((metrics?.total_processed_bytes || 0) / (1024 * 1024)).toFixed(2)} MB</strong>
          </span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "16px" }}>
        
        {/* Top Source IPs Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px 14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "10px" }}>
            <ArrowUpRight size={14} color="#38bdf8" />
            <h3 style={{ fontSize: "0.76rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Top Originating Source IPs
            </h3>
          </div>
          {topSources.length === 0 ? (
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", padding: "12px 0", textAlign: "center" }}>
              Waiting for incoming traffic flows...
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {topSources.map((src, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.74rem", fontFamily: "monospace" }}>
                  <span style={{ color: "#f8fafc" }}>{src.key}</span>
                  <span style={{ color: "#38bdf8", fontWeight: 700 }}>{src.count.toLocaleString()} flows</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Destination IPs Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px 14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "10px" }}>
            <ArrowDownRight size={14} color="#10b981" />
            <h3 style={{ fontSize: "0.76rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Top Targeted Destination IPs
            </h3>
          </div>
          {topDestinations.length === 0 ? (
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", padding: "12px 0", textAlign: "center" }}>
              Waiting for incoming traffic flows...
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {topDestinations.map((dst, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.74rem", fontFamily: "monospace" }}>
                  <span style={{ color: "#f8fafc" }}>{dst.key}</span>
                  <span style={{ color: "#10b981", fontWeight: 700 }}>{dst.count.toLocaleString()} flows</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Destination Ports Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px 14px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "10px" }}>
            <Hash size={14} color="#c084fc" />
            <h3 style={{ fontSize: "0.76rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Top Targeted Services / Ports
            </h3>
          </div>
          {topPorts.length === 0 ? (
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", padding: "12px 0", textAlign: "center" }}>
              Waiting for incoming traffic flows...
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              {topPorts.map((p, i) => {
                const portLabel = p.key === "443" ? "HTTPS (443)" : p.key === "80" ? "HTTP (80)" : p.key === "53" ? "DNS (53)" : `Port ${p.key}`;
                return (
                  <div key={i} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.74rem", fontFamily: "monospace" }}>
                    <span style={{ color: "#f8fafc" }}>{portLabel}</span>
                    <span style={{ color: "#c084fc", fontWeight: 700 }}>{p.count.toLocaleString()} pkts</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
