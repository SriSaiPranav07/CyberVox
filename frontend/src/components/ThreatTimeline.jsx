import React from "react";
import { Clock, ShieldAlert, Radio, Flame, Search, UploadCloud, Globe, ArrowRight } from "lucide-react";

export function ThreatTimeline({ alerts, onSelectAlert, selectedAlert }) {
  // Take last 15 alerts for visual timeline sequence
  const timelineAlerts = (alerts || []).slice(0, 15);

  const getIcon = (threatCls, cat) => {
    const t = (threatCls || "").toUpperCase();
    const c = (typeof cat === "object" ? cat.value : cat || "").toUpperCase();
    if (t.includes("SYN") || t.includes("UDP") || t.includes("DDOS") || c.includes("DDOS")) return { icon: Flame, color: "#ef4444" };
    if (t.includes("C2") || c.includes("C2")) return { icon: Radio, color: "#f59e0b" };
    if (t.includes("DGA") || t.includes("DNS") || c.includes("DNS")) return { icon: Globe, color: "#3b82f6" };
    if (t.includes("TLS") || t.includes("JA3") || c.includes("ENCRYPTED")) return { icon: ShieldAlert, color: "#8b5cf6" };
    if (t.includes("SCAN") || t.includes("RECON") || c.includes("RECON")) return { icon: Search, color: "#06b6d4" };
    return { icon: UploadCloud, color: "#ec4899" };
  };

  return (
    <div className="glass-panel" style={{ padding: "18px 20px", height: "100%", display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Clock size={16} color="#38bdf8" />
          <h2 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc" }}>
            THREAT TIMELINE & CORRELATION SEQUENCE
          </h2>
        </div>
        <span style={{ fontSize: "0.70rem", color: "var(--text-muted)" }}>
          Chronological Event Sequence
        </span>
      </div>

      {timelineAlerts.length === 0 ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: "0.78rem", padding: "40px 0" }}>
          No active threats detected. Timeline is listening...
        </div>
      ) : (
        <div style={{ flex: 1, overflowY: "auto", maxHeight: "400px", paddingRight: "4px" }}>
          <div style={{ position: "relative", paddingLeft: "24px" }}>
            {/* Vertical timeline track */}
            <div style={{
              position: "absolute",
              left: "8px",
              top: "4px",
              bottom: "4px",
              width: "2px",
              background: "rgba(255, 255, 255, 0.08)"
            }} />

            {timelineAlerts.map((a, idx) => {
              const { icon: Icon, color } = getIcon(a.threat_class, a.threat_category);
              const timeStr = a.timestamp ? a.timestamp.split("T")[1]?.replace("Z", "") : "Just now";
              const isSelected = selectedAlert?.flow_id === a.flow_id;

              return (
                <div
                  key={idx}
                  onClick={() => onSelectAlert(a)}
                  style={{
                    position: "relative",
                    marginBottom: "12px",
                    padding: "8px 12px",
                    background: isSelected ? "rgba(59, 130, 246, 0.2)" : "rgba(15, 23, 42, 0.6)",
                    border: isSelected ? "1px solid #38bdf8" : "1px solid var(--border-subtle)",
                    borderRadius: "6px",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                >
                  {/* Timeline node dot */}
                  <div style={{
                    position: "absolute",
                    left: "-20px",
                    top: "12px",
                    width: "10px",
                    height: "10px",
                    borderRadius: "50%",
                    background: color,
                    boxShadow: `0 0 8px ${color}`
                  }} />

                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "2px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <Icon size={13} color={color} />
                      <span style={{ fontSize: "0.76rem", fontWeight: 700, color: "#f8fafc" }}>
                        {a.threat_class}
                      </span>
                    </div>
                    <span style={{ fontSize: "0.68rem", fontFamily: "monospace", color: "var(--text-muted)" }}>
                      {timeStr}
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.68rem", color: "var(--text-secondary)" }}>
                    <span style={{ fontFamily: "monospace" }}>{a.source_ip} &rarr; {a.destination_ip}</span>
                    <span style={{ color: color, fontWeight: 700 }}>{Math.round(a.confidence * 100)}% Conf</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
