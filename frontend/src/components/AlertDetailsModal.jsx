import React from "react";
import { X, ShieldAlert, CheckCircle, Info, Lock, ArrowRight, ExternalLink } from "lucide-react";

export function AlertDetailsModal({ alert, onClose }) {
  if (!alert) return null;

  const sevStr = (typeof alert.severity === "object" ? alert.severity.value : alert.severity) || "LOW";
  const confPercent = Math.round(alert.confidence * 100);

  return (
    <div style={{
      position: "fixed",
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: "rgba(3, 7, 18, 0.82)",
      backdropFilter: "blur(8px)",
      zIndex: 100,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "20px"
    }}>
      <div className="glass-panel" style={{
        width: "100%",
        maxWidth: "750px",
        maxHeight: "90vh",
        overflowY: "auto",
        background: "#0d1322",
        border: "1px solid rgba(59, 130, 246, 0.4)",
        borderRadius: "12px",
        boxShadow: "0 20px 40px rgba(0,0,0,0.6)"
      }}>
        {/* Modal Header */}
        <div style={{
          padding: "16px 20px",
          borderBottom: "1px solid var(--border-subtle)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          background: "rgba(15, 23, 42, 0.8)"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{
              width: "32px",
              height: "32px",
              borderRadius: "6px",
              background: sevStr === "CRITICAL" ? "rgba(244, 63, 94, 0.2)" : "rgba(245, 158, 11, 0.2)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center"
            }}>
              <ShieldAlert size={18} color={sevStr === "CRITICAL" ? "#f43f5e" : "#f59e0b"} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <h2 style={{ fontSize: "1.05rem", fontWeight: 700, color: "#f8fafc" }}>
                  {alert.threat_class}
                </h2>
                <span className={sevStr === "CRITICAL" ? "badge-critical" : "badge-high"} style={{ padding: "2px 6px", borderRadius: "4px", fontSize: "0.68rem", fontWeight: 700 }}>
                  {sevStr}
                </span>
              </div>
              <p style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontFamily: "monospace" }}>
                Flow ID: {alert.flow_id} | Ingest Timestamp: {alert.timestamp}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              padding: "4px"
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: "20px" }}>
          
          {/* Top Quick Bar: Confidence & Network Path */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "16px" }}>
            
            {/* Confidence Card */}
            <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: "0.70rem", color: "var(--text-muted)", marginBottom: "4px", fontWeight: 600 }}>
                EVIDENCE CONFIDENCE SCORE
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
                <span style={{ fontSize: "1.3rem", fontWeight: 800, color: "#f8fafc" }}>
                  {alert.confidence.toFixed(2)}
                </span>
                <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                  ({confPercent}% Corroborated)
                </span>
              </div>
              <div style={{ width: "100%", height: "6px", background: "rgba(255,255,255,0.08)", borderRadius: "3px", overflow: "hidden" }}>
                <div style={{ width: `${confPercent}%`, height: "100%", background: "linear-gradient(90deg, #38bdf8, #10b981)" }} />
              </div>
            </div>

            {/* Network Endpoints Card */}
            <div style={{ background: "rgba(15, 23, 42, 0.6)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: "0.70rem", color: "var(--text-muted)", marginBottom: "4px", fontWeight: 600 }}>
                NETWORK CONNECTION (READ-ONLY CAPTURE)
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", fontFamily: "monospace", fontSize: "0.82rem", marginTop: "6px" }}>
                <span style={{ color: "#38bdf8", fontWeight: 700 }}>{alert.source_ip}:{alert.source_port}</span>
                <ArrowRight size={14} color="var(--text-muted)" />
                <span style={{ color: "#f8fafc", fontWeight: 700 }}>{alert.destination_ip}:{alert.destination_port}</span>
              </div>
              <div style={{ fontSize: "0.70rem", color: "var(--text-muted)", marginTop: "6px" }}>
                Protocol: {alert.protocol} | Latency: {alert.processing_latency_ms || 0.24} ms
              </div>
            </div>

          </div>

          {/* Explanation Banner */}
          <div style={{
            background: "rgba(59, 130, 246, 0.1)",
            border: "1px solid rgba(59, 130, 246, 0.3)",
            borderRadius: "8px",
            padding: "12px 14px",
            marginBottom: "16px",
            display: "flex",
            gap: "10px"
          }}>
            <Info size={18} color="#60a5fa" style={{ flexShrink: 0, marginTop: "2px" }} />
            <div>
              <div style={{ fontSize: "0.75rem", fontWeight: 700, color: "#93c5fd", marginBottom: "2px" }}>
                Detection Engine Interpretation
              </div>
              <div style={{ fontSize: "0.80rem", color: "#f1f5f9", lineHeight: "1.4" }}>
                {alert.explanation}
              </div>
            </div>
          </div>

          {/* Evidence Details Table */}
          <div style={{ marginBottom: "16px" }}>
            <h3 style={{ fontSize: "0.80rem", fontWeight: 700, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
              Supporting Technical Evidence (Observed vs Baseline)
            </h3>
            
            <div style={{ borderRadius: "8px", border: "1px solid var(--border-subtle)", overflow: "hidden" }}>
              <table className="soc-table" style={{ fontSize: "0.78rem" }}>
                <thead>
                  <tr>
                    <th>Feature Metric</th>
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
                        <td style={{ color: "var(--text-secondary)", fontSize: "0.74rem" }}>
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
                        <td><span style={{ color: "#fb7185", fontWeight: 700 }}>Anomalous</span></td>
                        <td style={{ color: "var(--text-secondary)", fontSize: "0.74rem" }}>Signal corroboration identified by hybrid detection engine.</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Non-Negotiable Enclave Guarantee Notice */}
          <div style={{
            background: "rgba(16, 185, 129, 0.08)",
            border: "1px solid rgba(16, 185, 129, 0.25)",
            borderRadius: "8px",
            padding: "10px 14px",
            display: "flex",
            alignItems: "center",
            gap: "10px"
          }}>
            <Lock size={16} color="#10b981" />
            <div style={{ fontSize: "0.72rem", color: "#6ee7b7" }}>
              <strong>Enclave Intelligence Guarantee:</strong> No return packets were transmitted, no target systems were probed, and encrypted payloads were analyzed strictly via metadata without decryption.
            </div>
          </div>

        </div>

        {/* Modal Footer */}
        <div style={{
          padding: "12px 20px",
          borderTop: "1px solid var(--border-subtle)",
          display: "flex",
          justifyContent: "flex-end",
          background: "rgba(15, 23, 42, 0.8)"
        }}>
          <button
            onClick={onClose}
            style={{
              background: "rgba(255, 255, 255, 0.1)",
              border: "1px solid var(--border-subtle)",
              color: "#f8fafc",
              padding: "6px 14px",
              borderRadius: "6px",
              fontSize: "0.78rem",
              fontWeight: 600,
              cursor: "pointer"
            }}
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
