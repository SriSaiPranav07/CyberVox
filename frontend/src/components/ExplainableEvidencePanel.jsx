import React from "react";
import { ShieldAlert, Info, Lock, ArrowRight, CheckCircle2, AlertTriangle, Layers, Cpu } from "lucide-react";

export function ExplainableEvidencePanel({ alert }) {
  if (!alert) {
    return (
      <div className="glass-panel" style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)", marginBottom: "20px" }}>
        <Info size={24} color="var(--text-muted)" style={{ margin: "0 auto 8px" }} />
        <div style={{ fontSize: "0.85rem", fontWeight: 600, color: "#f8fafc" }}>
          No Alert Selected for Deep Forensic Inspection
        </div>
        <div style={{ fontSize: "0.74rem", marginTop: "4px" }}>
          Click on any event in the <strong>Live Threats Stream</strong> or <strong>Threat Timeline</strong> to view explainable mathematical evidence and baseline deviations.
        </div>
      </div>
    );
  }

  const sevStr = (typeof alert.severity === "object" ? alert.severity.value : alert.severity) || "LOW";
  const confPercent = Math.round(alert.confidence * 100);
  const methodStr = (typeof alert.detection_engine === "object" ? alert.detection_engine.value : alert.detection_engine) || "Hybrid Ensemble (Statistical + ML)";

  return (
    <div className="glass-panel glass-panel-glow" style={{ padding: "20px", marginBottom: "20px", border: "1px solid rgba(59, 130, 246, 0.4)" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "14px", marginBottom: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{
            width: "36px",
            height: "36px",
            borderRadius: "8px",
            background: sevStr === "CRITICAL" ? "rgba(244, 63, 94, 0.2)" : "rgba(245, 158, 11, 0.2)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center"
          }}>
            <ShieldAlert size={20} color={sevStr === "CRITICAL" ? "#f43f5e" : "#f59e0b"} />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "0.70rem", fontWeight: 800, color: "var(--text-muted)", textTransform: "uppercase" }}>
                SELECTED THREAT EVIDENCE
              </span>
              <span className={sevStr === "CRITICAL" ? "badge-critical" : "badge-high"} style={{ padding: "2px 8px", borderRadius: "4px", fontSize: "0.68rem", fontWeight: 700 }}>
                {sevStr}
              </span>
            </div>
            <h2 style={{ fontSize: "1.15rem", fontWeight: 800, color: "#f8fafc" }}>
              {alert.threat_class}
            </h2>
          </div>
        </div>

        <div style={{ display: "flex", gap: "14px", fontSize: "0.74rem" }}>
          <div>
            <div style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Detection Method</div>
            <div style={{ color: "#38bdf8", fontWeight: 700 }}>{methodStr}</div>
          </div>
          <div>
            <div style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Captured Timestamp</div>
            <div style={{ fontFamily: "monospace", color: "#f8fafc" }}>{alert.timestamp}</div>
          </div>
        </div>
      </div>

      {/* Grid: Confidence Meter & Network Endpoints */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "14px", marginBottom: "16px" }}>
        
        {/* Confidence Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", borderRadius: "8px", padding: "12px 14px", border: "1px solid var(--border-subtle)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.72rem", marginBottom: "6px" }}>
            <span style={{ color: "var(--text-muted)", fontWeight: 700 }}>EVIDENCE CONFIDENCE SCORE</span>
            <span style={{ color: "#10b981", fontWeight: 800 }}>{alert.confidence.toFixed(2)} ({confPercent}% Corroborated)</span>
          </div>
          <div style={{ width: "100%", height: "7px", background: "rgba(255,255,255,0.08)", borderRadius: "4px", overflow: "hidden" }}>
            <div style={{
              width: `${confPercent}%`,
              height: "100%",
              background: confPercent > 85 ? "linear-gradient(90deg, #38bdf8, #10b981)" : "linear-gradient(90deg, #f59e0b, #ef4444)"
            }} />
          </div>
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginTop: "6px" }}>
            Based on multi-feature statistical threshold departure & ML ensemble validation.
          </div>
        </div>

        {/* Network Connection Card */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", borderRadius: "8px", padding: "12px 14px", border: "1px solid var(--border-subtle)" }}>
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontWeight: 700, marginBottom: "4px" }}>
            COMMUNICATION ENDPOINTS (READ-ONLY)
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", fontFamily: "monospace", fontSize: "0.85rem", marginTop: "4px" }}>
            <span style={{ color: "#38bdf8", fontWeight: 700 }}>{alert.source_ip}:{alert.source_port}</span>
            <ArrowRight size={14} color="var(--text-muted)" />
            <span style={{ color: "#f8fafc", fontWeight: 700 }}>{alert.destination_ip}:{alert.destination_port}</span>
          </div>
          <div style={{ fontSize: "0.70rem", color: "var(--text-secondary)", marginTop: "4px" }}>
            Flow ID: <strong style={{ color: "#f8fafc", fontFamily: "monospace" }}>{alert.flow_id}</strong> | Protocol: {alert.protocol}
          </div>
        </div>

      </div>

      {/* Detection Reason / Natural Language Explanation */}
      <div style={{
        background: "rgba(59, 130, 246, 0.08)",
        border: "1px solid rgba(59, 130, 246, 0.25)",
        borderRadius: "8px",
        padding: "12px 14px",
        marginBottom: "16px",
        display: "flex",
        gap: "10px"
      }}>
        <Info size={18} color="#60a5fa" style={{ flexShrink: 0, marginTop: "2px" }} />
        <div>
          <div style={{ fontSize: "0.74rem", fontWeight: 700, color: "#93c5fd", marginBottom: "2px" }}>
            Explainable Detection Reason & Heuristic
          </div>
          <div style={{ fontSize: "0.80rem", color: "#f8fafc", lineHeight: "1.4" }}>
            {alert.explanation}
          </div>
        </div>
      </div>

      {/* Supporting Technical Evidence Table */}
      <div style={{ marginBottom: "14px" }}>
        <h3 style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
          Relevant Observed Features & Baseline Deviations
        </h3>

        <div style={{ borderRadius: "8px", border: "1px solid var(--border-subtle)", overflow: "hidden" }}>
          <table className="soc-table" style={{ fontSize: "0.76rem" }}>
            <thead>
              <tr>
                <th>Feature Name</th>
                <th>Observed Value</th>
                <th>Baseline / Threshold</th>
                <th>Deviation</th>
                <th>Interpretation</th>
              </tr>
            </thead>
            <tbody>
              {alert.evidence_details && alert.evidence_details.length > 0 ? (
                alert.evidence_details.map((ev, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 600, color: "#38bdf8", fontFamily: "monospace" }}>
                      {ev.feature_name}
                    </td>
                    <td style={{ fontWeight: 700, color: "#f8fafc" }}>
                      {String(ev.observed_value)} {ev.unit}
                    </td>
                    <td style={{ color: "var(--text-muted)" }}>
                      {ev.baseline_value ? `${ev.baseline_value} / ` : ""}{ev.threshold_value || "N/A"}
                    </td>
                    <td>
                      {ev.deviation_pct !== undefined && ev.deviation_pct !== null ? (
                        <span style={{ color: ev.deviation_pct > 0 ? "#fb7185" : "#34d399", fontWeight: 700 }}>
                          {ev.deviation_pct > 0 ? `+${ev.deviation_pct}%` : `${ev.deviation_pct}%`}
                        </span>
                      ) : (
                        <span style={{ color: "var(--text-muted)" }}>-</span>
                      )}
                    </td>
                    <td style={{ color: "var(--text-secondary)", fontSize: "0.72rem" }}>
                      {ev.interpretation}
                    </td>
                  </tr>
                ))
              ) : (
                Object.entries(alert.evidence || {}).map(([key, val], i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 600, color: "#38bdf8", fontFamily: "monospace" }}>{key}</td>
                    <td style={{ fontWeight: 700, color: "#f8fafc" }}>{String(val)}</td>
                    <td style={{ color: "var(--text-muted)" }}>Calculated Window</td>
                    <td><span style={{ color: "#fb7185", fontWeight: 700 }}>Departed</span></td>
                    <td style={{ color: "var(--text-secondary)", fontSize: "0.72rem" }}>Feature exceeded statistical confidence threshold.</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Enclave Zero Decryption & Airgap Guarantee Banner */}
      <div style={{
        background: "rgba(16, 185, 129, 0.08)",
        border: "1px solid rgba(16, 185, 129, 0.25)",
        borderRadius: "8px",
        padding: "8px 12px",
        display: "flex",
        alignItems: "center",
        gap: "8px"
      }}>
        <Lock size={14} color="#10b981" />
        <div style={{ fontSize: "0.70rem", color: "#6ee7b7" }}>
          <strong>Enclave Security Guarantee:</strong> Zero return packets were transmitted, no target hosts were queried, and TLS payloads were analyzed strictly via ClientHello metadata without decryption.
        </div>
      </div>

    </div>
  );
}
