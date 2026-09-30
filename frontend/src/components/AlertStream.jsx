import React, { useState } from "react";
import { AlertCircle, Filter, Search, ChevronRight, Pause, Play } from "lucide-react";

export function AlertStream({ alerts, onSelectAlert, activeFilter, setActiveFilter }) {
  const [searchTerm, setSearchTerm] = useState("");
  const [isPaused, setIsPaused] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      searchTerm === "" ||
      alert.flow_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source_ip.includes(searchTerm) ||
      alert.destination_ip.includes(searchTerm) ||
      alert.threat_class.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      severityFilter === "ALL" ||
      alert.severity === severityFilter ||
      alert.severity?.value === severityFilter;

    const matchesCategory =
      !activeFilter ||
      alert.threat_category === activeFilter ||
      alert.threat_category?.value === activeFilter ||
      alert.threat_class.includes(activeFilter);

    return matchesSearch && matchesSeverity && matchesCategory;
  });

  const getSeverityBadgeClass = (sev) => {
    const s = (typeof sev === "object" ? sev.value : sev) || "LOW";
    if (s === "CRITICAL") return "badge-critical";
    if (s === "HIGH") return "badge-high";
    if (s === "MEDIUM") return "badge-medium";
    return "badge-low";
  };

  return (
    <div className="glass-panel" style={{ padding: "18px", marginBottom: "20px" }}>
      {/* Header & Controls */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px", marginBottom: "14px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <AlertCircle size={18} color="#f43f5e" />
            <h2 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc" }}>
              LIVE THREAT ALERT STREAM
            </h2>
          </div>
          <span style={{
            fontSize: "0.72rem",
            padding: "2px 8px",
            background: "rgba(244, 63, 94, 0.15)",
            color: "#fb7185",
            borderRadius: "12px",
            fontWeight: 700
          }}>
            {filteredAlerts.length} Captured
          </span>
          {activeFilter && (
            <span style={{
              fontSize: "0.72rem",
              padding: "2px 8px",
              background: "rgba(59, 130, 246, 0.2)",
              color: "#60a5fa",
              borderRadius: "4px",
              cursor: "pointer"
            }} onClick={() => setActiveFilter(null)}>
              Filtering: {activeFilter} &times;
            </span>
          )}
        </div>

        {/* Filter controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {/* Search bar */}
          <div style={{ position: "relative", minWidth: "180px" }}>
            <Search size={14} color="var(--text-muted)" style={{ position: "absolute", left: "10px", top: "50%", transform: "translateY(-50%)" }} />
            <input
              type="text"
              placeholder="Search IP, flow, threat..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: "rgba(15, 23, 42, 0.8)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "6px",
                padding: "6px 10px 6px 30px",
                color: "#f8fafc",
                fontSize: "0.78rem",
                width: "100%",
                outline: "none"
              }}
            />
          </div>

          {/* Severity filter pills */}
          <div style={{ display: "flex", gap: "4px" }}>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? "rgba(255, 255, 255, 0.15)" : "rgba(15, 23, 42, 0.6)",
                  border: "1px solid var(--border-subtle)",
                  color: severityFilter === sev ? "#ffffff" : "var(--text-secondary)",
                  padding: "4px 8px",
                  borderRadius: "4px",
                  fontSize: "0.70rem",
                  fontWeight: 600,
                  cursor: "pointer"
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Pause / Resume stream */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            style={{
              background: isPaused ? "rgba(245, 158, 11, 0.2)" : "rgba(15, 23, 42, 0.6)",
              border: "1px solid var(--border-subtle)",
              color: isPaused ? "#fbbf24" : "var(--text-secondary)",
              padding: "4px 8px",
              borderRadius: "4px",
              fontSize: "0.70rem",
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "4px"
            }}
          >
            {isPaused ? <Play size={12} /> : <Pause size={12} />}
            {isPaused ? "Resume Feed" : "Pause Feed"}
          </button>
        </div>
      </div>

      {/* Table of Alerts */}
      <div style={{ maxHeight: "380px", overflowY: "auto", borderRadius: "6px", border: "1px solid var(--border-subtle)" }}>
        {filteredAlerts.length === 0 ? (
          <div style={{ padding: "32px", textAlign: "center", color: "var(--text-muted)", fontSize: "0.82rem" }}>
            No threat alerts matched current filter. Passive stream listening...
          </div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Threat Class</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Origin &rarr; Target</th>
                <th>Proto</th>
                <th>Key Evidence</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((alert, idx) => {
                const sevStr = (typeof alert.severity === "object" ? alert.severity.value : alert.severity) || "LOW";
                const confPercent = Math.round(alert.confidence * 100);
                return (
                  <tr key={idx} onClick={() => onSelectAlert(alert)}>
                    <td style={{ fontSize: "0.75rem", fontFamily: "monospace", color: "var(--text-muted)" }}>
                      {alert.timestamp ? alert.timestamp.split("T")[1]?.replace("Z", "") : "Now"}
                    </td>
                    <td>
                      <span style={{ fontWeight: 700, color: "#f8fafc", fontSize: "0.78rem" }}>
                        {alert.threat_class}
                      </span>
                    </td>
                    <td>
                      <span className={getSeverityBadgeClass(sevStr)} style={{ padding: "2px 6px", borderRadius: "4px", fontSize: "0.68rem", fontWeight: 700 }}>
                        {sevStr}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <div style={{ width: "45px", height: "5px", background: "rgba(255,255,255,0.1)", borderRadius: "3px", overflow: "hidden" }}>
                          <div style={{
                            width: `${confPercent}%`,
                            height: "100%",
                            background: confPercent > 85 ? "#10b981" : confPercent > 70 ? "#38bdf8" : "#f59e0b"
                          }} />
                        </div>
                        <span style={{ fontSize: "0.72rem", color: "var(--text-secondary)", fontWeight: 600 }}>
                          {alert.confidence.toFixed(2)}
                        </span>
                      </div>
                    </td>
                    <td style={{ fontSize: "0.75rem", fontFamily: "monospace" }}>
                      <span style={{ color: "#38bdf8" }}>{alert.source_ip}:{alert.source_port}</span>
                      <span style={{ color: "var(--text-muted)", margin: "0 4px" }}>&rarr;</span>
                      <span style={{ color: "#f8fafc" }}>{alert.destination_ip}:{alert.destination_port}</span>
                    </td>
                    <td>
                      <span style={{ fontSize: "0.70rem", color: "var(--text-secondary)", background: "rgba(255,255,255,0.05)", padding: "2px 4px", borderRadius: "3px" }}>
                        {alert.protocol}
                      </span>
                    </td>
                    <td style={{ fontSize: "0.72rem", color: "var(--text-muted)", maxWidth: "220px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {JSON.stringify(alert.evidence).slice(0, 45)}...
                    </td>
                    <td>
                      <button style={{
                        background: "rgba(59, 130, 246, 0.15)",
                        border: "1px solid rgba(59, 130, 246, 0.3)",
                        color: "#60a5fa",
                        padding: "3px 8px",
                        borderRadius: "4px",
                        fontSize: "0.70rem",
                        cursor: "pointer",
                        display: "flex",
                        alignItems: "center",
                        gap: "2px"
                      }}>
                        Inspect <ChevronRight size={12} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
