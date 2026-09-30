import React, { useState } from "react";
import { AlertCircle, Search, ChevronRight, Filter, ShieldCheck, Flame, Radio, Globe, ShieldAlert, UploadCloud } from "lucide-react";

export function AlertFeed({ alerts, onSelectAlert, selectedAlert, activeCategoryFilter, setActiveCategoryFilter }) {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const filteredAlerts = (alerts || []).filter((alert) => {
    const matchesSearch =
      searchTerm === "" ||
      alert.flow_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source_ip.includes(searchTerm) ||
      alert.destination_ip.includes(searchTerm) ||
      alert.threat_class.toLowerCase().includes(searchTerm.toLowerCase());

    const sevStr = (typeof alert.severity === "object" ? alert.severity.value : alert.severity) || "LOW";
    const matchesSeverity = severityFilter === "ALL" || sevStr === severityFilter;

    const catStr = (typeof alert.threat_category === "object" ? alert.threat_category.value : alert.threat_category) || "";
    const matchesCategory =
      !activeCategoryFilter ||
      catStr.includes(activeCategoryFilter) ||
      alert.threat_class.includes(activeCategoryFilter);

    return matchesSearch && matchesSeverity && matchesCategory;
  });

  const getSeverityBadge = (sev) => {
    const s = (typeof sev === "object" ? sev.value : sev) || "LOW";
    if (s === "CRITICAL") return "badge-critical";
    if (s === "HIGH") return "badge-high";
    if (s === "MEDIUM") return "badge-medium";
    return "badge-low";
  };

  return (
    <div className="glass-panel" style={{ padding: "18px 20px", height: "100%", display: "flex", flexDirection: "column" }}>
      {/* Header & Filter Controls */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "10px", marginBottom: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <AlertCircle size={16} color="#f43f5e" />
          <h2 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc" }}>
            LIVE THREAT ALERTS STREAM
          </h2>
          <span style={{
            fontSize: "0.68rem",
            padding: "2px 8px",
            background: "rgba(244, 63, 94, 0.15)",
            color: "#fb7185",
            borderRadius: "12px",
            fontWeight: 700
          }}>
            {filteredAlerts.length} Captured
          </span>
          {activeCategoryFilter && (
            <span
              onClick={() => setActiveCategoryFilter(null)}
              style={{
                fontSize: "0.68rem",
                padding: "2px 8px",
                background: "rgba(59, 130, 246, 0.2)",
                color: "#60a5fa",
                borderRadius: "4px",
                cursor: "pointer",
                fontWeight: 600
              }}
            >
              Filtering: {activeCategoryFilter} &times;
            </span>
          )}
        </div>

        {/* Filter Toolbar */}
        <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
          {/* Search box */}
          <div style={{ position: "relative", minWidth: "150px" }}>
            <Search size={12} color="var(--text-muted)" style={{ position: "absolute", left: "8px", top: "50%", transform: "translateY(-50%)" }} />
            <input
              type="text"
              placeholder="Search IP, flow, threat..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: "rgba(15, 23, 42, 0.8)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "6px",
                padding: "4px 8px 4px 26px",
                color: "#f8fafc",
                fontSize: "0.74rem",
                width: "100%",
                outline: "none"
              }}
            />
          </div>

          {/* Severity Pills */}
          <div style={{ display: "flex", gap: "4px" }}>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  background: severityFilter === sev ? "rgba(255, 255, 255, 0.15)" : "rgba(15, 23, 42, 0.6)",
                  border: "1px solid var(--border-subtle)",
                  color: severityFilter === sev ? "#ffffff" : "var(--text-secondary)",
                  padding: "3px 6px",
                  borderRadius: "4px",
                  fontSize: "0.68rem",
                  fontWeight: 600,
                  cursor: "pointer"
                }}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Feed List */}
      <div style={{ flex: 1, overflowY: "auto", maxHeight: "400px" }}>
        {filteredAlerts.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontSize: "0.80rem" }}>
            No active threats detected. Waiting for replayed or simulated traffic...
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {filteredAlerts.map((alert, idx) => {
              const sevStr = (typeof alert.severity === "object" ? alert.severity.value : alert.severity) || "LOW";
              const timeStr = alert.timestamp ? alert.timestamp.split("T")[1]?.replace("Z", "") : "Now";
              const isSelected = selectedAlert?.flow_id === alert.flow_id;
              const evidenceSummary = Object.entries(alert.evidence || {})
                .map(([k, v]) => `${k}: ${v}`)
                .slice(0, 3)
                .join(" | ");

              return (
                <div
                  key={idx}
                  onClick={() => onSelectAlert(alert)}
                  style={{
                    background: isSelected ? "rgba(59, 130, 246, 0.18)" : "rgba(15, 23, 42, 0.65)",
                    border: isSelected ? "1px solid #38bdf8" : "1px solid var(--border-subtle)",
                    borderRadius: "8px",
                    padding: "10px 14px",
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px"
                  }}
                >
                  {/* Top Bar: Time, Severity, Threat Type, Confidence */}
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontSize: "0.72rem", fontFamily: "monospace", color: "var(--text-muted)" }}>
                        {timeStr}
                      </span>
                      <span className={getSeverityBadge(sevStr)} style={{ padding: "2px 6px", borderRadius: "4px", fontSize: "0.66rem", fontWeight: 700 }}>
                        {sevStr}
                      </span>
                      <span style={{ fontSize: "0.82rem", fontWeight: 700, color: "#f8fafc" }}>
                        {alert.threat_class}
                      </span>
                    </div>

                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <span style={{ fontSize: "0.74rem", fontWeight: 700, color: "#10b981" }}>
                        Confidence: {Math.round(alert.confidence * 100)}%
                      </span>
                      <ChevronRight size={14} color="var(--text-muted)" />
                    </div>
                  </div>

                  {/* Flow endpoints */}
                  <div style={{ fontSize: "0.72rem", fontFamily: "monospace", color: "var(--text-secondary)", display: "flex", gap: "10px" }}>
                    <span>Flow: <strong style={{ color: "#38bdf8" }}>{alert.flow_id}</strong></span>
                    <span>Origin: <strong>{alert.source_ip}:{alert.source_port}</strong> &rarr; <strong>{alert.destination_ip}:{alert.destination_port}</strong> ({alert.protocol})</span>
                  </div>

                  {/* Short Evidence Summary */}
                  <div style={{ fontSize: "0.70rem", color: "var(--text-muted)", background: "rgba(9, 14, 23, 0.5)", padding: "4px 8px", borderRadius: "4px", textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>
                    <strong style={{ color: "#94a3b8" }}>Evidence:</strong> {evidenceSummary}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
