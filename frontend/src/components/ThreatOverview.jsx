import React from "react";
import { Flame, Radio, Globe, ShieldAlert, Search, UploadCloud } from "lucide-react";

export function ThreatOverview({ stats, onSelectCategory }) {
  const categories = [
    {
      id: "DDOS",
      name: "Volumetric / Protocol DDoS",
      count: stats?.ddos_count || 0,
      desc: "SYN floods, UDP reflection, spoofed origin floods",
      icon: Flame,
      color: "#ef4444"
    },
    {
      id: "C2",
      name: "Botnet C2 Beaconing",
      count: stats?.c2_count || 0,
      desc: "Inter-arrival cadence, low jitter CV, FFT periodicity",
      icon: Radio,
      color: "#f59e0b"
    },
    {
      id: "DNS",
      name: "DGA & DNS Tunnelling",
      count: stats?.dns_count || 0,
      desc: "Shannon entropy, hex chunks, TXT/NULL query depth",
      icon: Globe,
      color: "#3b82f6"
    },
    {
      id: "ENCRYPTED",
      name: "Encrypted Traffic (Metadata)",
      count: stats?.encrypted_count || 0,
      desc: "JA3/JA4 signatures, burst dispersion, NO payload decryption",
      icon: ShieldAlert,
      color: "#8b5cf6"
    },
    {
      id: "RECON",
      name: "Reconnaissance & Scanning",
      count: stats?.recon_count || 0,
      desc: "Horizontal subnet sweep, vertical port probing",
      icon: Search,
      color: "#06b6d4"
    },
    {
      id: "EXFILTRATION",
      name: "Potential Data Exfiltration",
      count: stats?.exfil_count || 0,
      desc: "Outbound/inbound byte asymmetry, egress volume spikes",
      icon: UploadCloud,
      color: "#ec4899"
    }
  ];

  return (
    <div className="glass-panel" style={{ padding: "18px", marginBottom: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "14px" }}>
        <div>
          <h2 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc" }}>
            THREAT DETECTION CATEGORIES (6 INDEPENDENT ENGINES)
          </h2>
          <p style={{ fontSize: "0.74rem", color: "var(--text-muted)" }}>
            Real-time multi-dimensional passive threat classification & evidence correlation
          </p>
        </div>
        <div style={{ display: "flex", gap: "8px", fontSize: "0.72rem" }}>
          <span style={{ color: "#fb7185" }}>Critical: {stats?.severity_breakdown?.CRITICAL || 0}</span>
          <span style={{ color: "var(--border-subtle)" }}>|</span>
          <span style={{ color: "#fbbf24" }}>High: {stats?.severity_breakdown?.HIGH || 0}</span>
          <span style={{ color: "var(--border-subtle)" }}>|</span>
          <span style={{ color: "#60a5fa" }}>Med: {stats?.severity_breakdown?.MEDIUM || 0}</span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px" }}>
        {categories.map((cat) => {
          const Icon = cat.icon;
          const hasDetections = cat.count > 0;
          return (
            <div
              key={cat.id}
              onClick={() => onSelectCategory(cat.id)}
              style={{
                background: hasDetections ? `rgba(${cat.color === "#ef4444" ? "239, 68, 68" : cat.color === "#f59e0b" ? "245, 158, 11" : cat.color === "#3b82f6" ? "59, 130, 246" : cat.color === "#8b5cf6" ? "139, 92, 246" : cat.color === "#06b6d4" ? "6, 182, 212" : "236, 72, 153"}, 0.08)` : "rgba(15, 23, 42, 0.4)",
                border: hasDetections ? `1px solid ${cat.color}40` : "1px solid var(--border-subtle)",
                borderRadius: "8px",
                padding: "12px",
                cursor: "pointer",
                transition: "all 0.15s ease",
                position: "relative"
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <Icon size={14} color={cat.color} />
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "#f1f5f9" }}>
                    {cat.name}
                  </span>
                </div>
                <span style={{
                  fontSize: "0.85rem",
                  fontWeight: 800,
                  color: hasDetections ? cat.color : "var(--text-muted)",
                  background: hasDetections ? `${cat.color}20` : "transparent",
                  padding: "1px 6px",
                  borderRadius: "4px"
                }}>
                  {cat.count}
                </span>
              </div>
              <p style={{ fontSize: "0.68rem", color: "var(--text-secondary)", lineHeight: "1.3" }}>
                {cat.desc}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
