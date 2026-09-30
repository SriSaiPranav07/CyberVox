import React, { useState, useEffect } from "react";
import { Globe, Radio, ShieldAlert, Cpu, EyeOff, Hash, Layers } from "lucide-react";
import { fetchRecentFlows, fetchModels } from "../services/api";

export function DeepInspector() {
  const [flows, setFlows] = useState([]);
  const [models, setModels] = useState([]);

  useEffect(() => {
    const load = async () => {
      try {
        const flowRes = await fetchRecentFlows(20);
        setFlows(flowRes.flows || []);
        const modRes = await fetchModels();
        setModels(modRes.models || []);
      } catch (e) {}
    };
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" }}>
      
      {/* Panel 1: Encrypted Traffic & DNS Metadata Inspector */}
      <div className="glass-panel" style={{ padding: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
          <EyeOff size={18} color="#f59e0b" />
          <h2 style={{ fontSize: "1.0rem", fontWeight: 700, color: "#f8fafc" }}>
            PASSIVE METADATA FORENSIC INSPECTOR
          </h2>
        </div>
        <p style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginBottom: "16px" }}>
          Observed metadata streams captured without payload decryption or active DNS resolution
        </p>

        <div style={{ maxHeight: "360px", overflowY: "auto", borderRadius: "6px", border: "1px solid var(--border-subtle)" }}>
          <table className="soc-table" style={{ fontSize: "0.74rem" }}>
            <thead>
              <tr>
                <th>Protocol</th>
                <th>Target</th>
                <th>Extracted Metadata</th>
                <th>Security Mode</th>
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ textAlign: "center", padding: "20px", color: "var(--text-muted)" }}>
                    Waiting for passive network flows...
                  </td>
                </tr>
              ) : (
                flows.map((f, i) => (
                  <tr key={i}>
                    <td>
                      <span style={{ fontWeight: 700, color: f.dns_query ? "#3b82f6" : f.ja3_hash ? "#8b5cf6" : "#06b6d4" }}>
                        {f.dns_query ? "DNS" : f.ja3_hash ? "TLS" : f.protocol}
                      </span>
                    </td>
                    <td style={{ fontFamily: "monospace", color: "#f8fafc" }}>
                      {f.destination_ip}:{f.destination_port}
                    </td>
                    <td style={{ fontFamily: "monospace", color: "var(--text-secondary)", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {f.dns_query ? `Q: ${f.dns_query}` : f.ja3_hash ? `JA3: ${f.ja3_hash.slice(0, 16)}...` : `${f.packet_count} pkts / ${f.byte_count} B`}
                    </td>
                    <td>
                      <span style={{ fontSize: "0.68rem", color: "#34d399", background: "rgba(16, 185, 129, 0.1)", padding: "2px 6px", borderRadius: "4px" }}>
                        READ-ONLY
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Panel 2: AI/ML Architecture & Model Inventory */}
      <div className="glass-panel" style={{ padding: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
          <Cpu size={18} color="#8b5cf6" />
          <h2 style={{ fontSize: "1.0rem", fontWeight: 700, color: "#f8fafc" }}>
            AI/ML MODEL INVENTORY & VALIDATION
          </h2>
        </div>
        <p style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginBottom: "16px" }}>
          Hybrid AI architecture: Supervised Classifiers + Unsupervised Outlier Isolation + Deterministic Rules
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {models.map((m, i) => (
            <div key={i} style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "12px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                <span style={{ fontSize: "0.82rem", fontWeight: 700, color: "#f8fafc" }}>
                  {m.name}
                </span>
                <span style={{ fontSize: "0.68rem", color: "#34d399", background: "rgba(16, 185, 129, 0.15)", padding: "2px 6px", borderRadius: "4px", fontWeight: 700 }}>
                  {m.status}
                </span>
              </div>
              <div style={{ fontSize: "0.70rem", color: "var(--text-secondary)", marginBottom: "4px" }}>
                Type: {m.type}
              </div>
              {m.macro_f1_score && (
                <div style={{ display: "flex", gap: "12px", fontSize: "0.72rem", color: "#38bdf8", fontWeight: 600 }}>
                  <span>Macro F1: {(m.macro_f1_score * 100).toFixed(2)}%</span>
                  <span>Precision: {(m.precision * 100).toFixed(2)}%</span>
                  <span>Recall: {(m.recall * 100).toFixed(2)}%</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
