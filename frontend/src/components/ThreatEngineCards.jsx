import React from "react";
import { Flame, Radio, Globe, ShieldAlert, Search, UploadCloud, Activity, CheckCircle2, AlertTriangle } from "lucide-react";

export function ThreatEngineCards({ stats, onSelectCategory, activeCategory }) {
  const categoryDetails = stats?.category_details || {};

  const engines = [
    {
      id: "DDOS",
      name: "Volumetric / Protocol DDoS",
      icon: Flame,
      color: "#ef4444",
      defaultMethod: "Statistical Velocity + ML Ensemble",
      desc: "SYN floods, UDP storms, amplification reflection"
    },
    {
      id: "C2",
      name: "Botnet C2 Beaconing",
      icon: Radio,
      color: "#f59e0b",
      defaultMethod: "IAT Jitter CV & FFT Periodicity",
      desc: "Robotic inter-arrival cadence, time-series regularity"
    },
    {
      id: "DNS",
      name: "DGA & DNS Tunnelling",
      icon: Globe,
      color: "#3b82f6",
      defaultMethod: "Shannon Entropy & N-Gram Perplexity",
      desc: "High-entropy domain labels, hex data tunnelling chunks"
    },
    {
      id: "ENCRYPTED",
      name: "Encrypted Traffic (Metadata)",
      icon: ShieldAlert,
      color: "#8b5cf6",
      defaultMethod: "JA3/JA4 Hashes & Packet Dispersion",
      desc: "Cobalt Strike JA3 matching without payload decryption"
    },
    {
      id: "RECON",
      name: "Reconnaissance & Scanning",
      icon: Search,
      color: "#06b6d4",
      defaultMethod: "Fan-Out Cardinality & Rate Analysis",
      desc: "Horizontal subnet discovery, vertical port probing"
    },
    {
      id: "EXFILTRATION",
      name: "Potential Data Exfiltration",
      icon: UploadCloud,
      color: "#ec4899",
      defaultMethod: "Asymmetric Byte Ratio & Egress Baseline",
      desc: "Unusual outbound payload transfers (>8.0x ratio)"
    }
  ];

  return (
    <div style={{ marginBottom: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
        <div>
          <h2 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc", letterSpacing: "-0.01em" }}>
            SIX THREAT DETECTION ENGINES (INDEPENDENT SUBSYSTEMS)
          </h2>
          <p style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
            Dynamic threat telemetry, corroboration confidence, and method breakdown
          </p>
        </div>
        <div style={{ display: "flex", gap: "10px", fontSize: "0.72rem" }}>
          <span style={{ color: "#fb7185", fontWeight: 700 }}>Critical: {stats?.severity_breakdown?.CRITICAL || 0}</span>
          <span style={{ color: "var(--border-subtle)" }}>|</span>
          <span style={{ color: "#fbbf24", fontWeight: 700 }}>High: {stats?.severity_breakdown?.HIGH || 0}</span>
          <span style={{ color: "var(--border-subtle)" }}>|</span>
          <span style={{ color: "#60a5fa", fontWeight: 700 }}>Medium: {stats?.severity_breakdown?.MEDIUM || 0}</span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "14px" }}>
        {engines.map((eng) => {
          const Icon = eng.icon;
          const info = categoryDetails[eng.id] || {};
          const count = info.count || (
            eng.id === "DDOS" ? stats?.ddos_count :
            eng.id === "C2" ? stats?.c2_count :
            eng.id === "DNS" ? stats?.dns_count :
            eng.id === "ENCRYPTED" ? stats?.encrypted_count :
            eng.id === "RECON" ? stats?.recon_count :
            stats?.exfil_count
          ) || 0;

          const isSelected = activeCategory === eng.id;
          const hasDetected = count > 0;
          const status = hasDetected ? "THREAT DETECTED" : "LISTENING / IDLE";

          return (
            <div
              key={eng.id}
              onClick={() => onSelectCategory(eng.id)}
              className="glass-panel"
              style={{
                padding: "14px 16px",
                border: isSelected
                  ? `1px solid ${eng.color}`
                  : hasDetected
                  ? `1px solid ${eng.color}50`
                  : "1px solid var(--border-subtle)",
                background: isSelected
                  ? "rgba(15, 23, 42, 0.95)"
                  : hasDetected
                  ? "rgba(15, 23, 42, 0.8)"
                  : "rgba(15, 23, 42, 0.5)",
                cursor: "pointer",
                position: "relative",
                transition: "all 0.15s ease"
              }}
            >
              {/* Top Row: Icon, Title, and Count */}
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "8px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <div style={{
                    width: "28px",
                    height: "28px",
                    borderRadius: "6px",
                    background: `${eng.color}18`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center"
                  }}>
                    <Icon size={16} color={eng.color} />
                  </div>
                  <div>
                    <h3 style={{ fontSize: "0.82rem", fontWeight: 700, color: "#f8fafc" }}>
                      {eng.name}
                    </h3>
                    <span style={{
                      fontSize: "0.65rem",
                      color: hasDetected ? eng.color : "var(--text-muted)",
                      fontWeight: 700
                    }}>
                      {status}
                    </span>
                  </div>
                </div>

                <div style={{
                  fontSize: "1.1rem",
                  fontWeight: 800,
                  color: hasDetected ? eng.color : "var(--text-muted)",
                  background: hasDetected ? `${eng.color}15` : "rgba(255, 255, 255, 0.04)",
                  padding: "2px 8px",
                  borderRadius: "6px"
                }}>
                  {count}
                </div>
              </div>

              {/* Dynamic Information Grid */}
              <div style={{
                background: "rgba(9, 14, 23, 0.5)",
                borderRadius: "6px",
                padding: "8px 10px",
                fontSize: "0.70rem",
                marginTop: "6px",
                display: "flex",
                flexDirection: "column",
                gap: "4px"
              }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--text-muted)" }}>Latest Event:</span>
                  <span style={{ fontWeight: 600, color: hasDetected ? "#f8fafc" : "var(--text-muted)" }}>
                    {info.latest_threat || (hasDetected ? "Active Anomaly" : "None")}
                  </span>
                </div>

                {hasDetected && info.latest_severity && (
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--text-muted)" }}>Severity / Conf:</span>
                    <span style={{ fontWeight: 700, color: info.latest_severity === "CRITICAL" ? "#fb7185" : "#fbbf24" }}>
                      {info.latest_severity} ({Math.round((info.latest_confidence || 0.95) * 100)}%)
                    </span>
                  </div>
                )}

                <div style={{ display: "flex", justifyContent: "space-between", borderTop: "1px solid rgba(255,255,255,0.04)", paddingTop: "4px", marginTop: "2px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Method:</span>
                  <span style={{ color: "#38bdf8", fontWeight: 600, fontSize: "0.66rem", maxWidth: "150px", textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>
                    {info.method || eng.defaultMethod}
                  </span>
                </div>
              </div>

            </div>
          );
        })}
      </div>
    </div>
  );
}
