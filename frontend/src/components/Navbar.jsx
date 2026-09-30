import React from "react";
import { Shield, Radio, Lock, EyeOff, Activity, RefreshCw, Cpu } from "lucide-react";

export function Navbar({ enclaveStatus, wsConnected, onReset, activeTab, setActiveTab }) {
  return (
    <header style={{
      borderBottom: "1px solid var(--border-subtle)",
      background: "rgba(11, 15, 25, 0.95)",
      backdropFilter: "blur(16px)",
      position: "sticky",
      top: 0,
      zIndex: 40,
      padding: "12px 24px"
    }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
        
        {/* Brand & System Mode */}
        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
          <div style={{
            width: "38px",
            height: "38px",
            borderRadius: "8px",
            background: "linear-gradient(135deg, #06b6d4, #3b82f6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 0 16px rgba(6, 182, 212, 0.4)"
          }}>
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <h1 style={{ fontSize: "1.1rem", fontWeight: 700, letterSpacing: "-0.02em", color: "#f8fafc" }}>
                SIH 2026 CYBER DEFENSE ENCLAVE
              </h1>
              <span style={{
                fontSize: "0.65rem",
                padding: "2px 6px",
                background: "rgba(59, 130, 246, 0.2)",
                color: "#60a5fa",
                borderRadius: "4px",
                fontWeight: 600,
                border: "1px solid rgba(59, 130, 246, 0.4)"
              }}>
                v2.0 PROTOTYPE
              </span>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Passive Network Threat Intelligence & ML Detection Platform
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div style={{ display: "flex", alignItems: "center", gap: "6px", background: "rgba(15, 23, 42, 0.8)", padding: "4px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
          {[
            { id: "dashboard", label: "SOC Live Operations" },
            { id: "replay", label: "PCAP & Attack Simulation" },
            { id: "benchmark", label: "Throughput Benchmark" },
            { id: "deep-inspector", label: "Deep Forensic Inspector" },
            { id: "enclave-audit", label: "Airgap Security Audit" }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                background: activeTab === tab.id ? "rgba(59, 130, 246, 0.2)" : "transparent",
                color: activeTab === tab.id ? "#38bdf8" : "var(--text-secondary)",
                border: activeTab === tab.id ? "1px solid rgba(56, 189, 248, 0.3)" : "1px solid transparent",
                padding: "6px 12px",
                borderRadius: "6px",
                fontSize: "0.78rem",
                fontWeight: 600,
                cursor: "pointer",
                transition: "all 0.15s ease"
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Enclave Security Invariants Badges */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          
          <div className="badge-enclave" style={{ display: "flex", alignItems: "center", gap: "6px", padding: "4px 10px", borderRadius: "6px", fontSize: "0.72rem", fontWeight: 600 }}>
            <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#10b981" }} className="pulse-emerald" />
            PASSIVE MONITORING: ACTIVE
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "6px", padding: "4px 10px", borderRadius: "6px", fontSize: "0.72rem", fontWeight: 600, background: "rgba(6, 182, 212, 0.12)", color: "#22d3ee", border: "1px solid rgba(6, 182, 212, 0.3)" }}>
            <Radio size={12} />
            READ-ONLY INGEST
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "6px", padding: "4px 10px", borderRadius: "6px", fontSize: "0.72rem", fontWeight: 600, background: "rgba(139, 92, 246, 0.12)", color: "#c084fc", border: "1px solid rgba(139, 92, 246, 0.3)" }}>
            <Lock size={12} />
            RETURN PATH: NONE
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "6px", padding: "4px 10px", borderRadius: "6px", fontSize: "0.72rem", fontWeight: 600, background: "rgba(245, 158, 11, 0.12)", color: "#fbbf24", border: "1px solid rgba(245, 158, 11, 0.3)" }}>
            <EyeOff size={12} />
            PAYLOAD DECRYPTION: DISABLED
          </div>

          <button
            onClick={onReset}
            title="Reset telemetry & alert buffer"
            style={{
              background: "rgba(255, 255, 255, 0.05)",
              border: "1px solid var(--border-subtle)",
              color: "var(--text-secondary)",
              padding: "6px 10px",
              borderRadius: "6px",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "4px",
              fontSize: "0.72rem"
            }}
          >
            <RefreshCw size={12} />
            Reset
          </button>
        </div>

      </div>
    </header>
  );
}
