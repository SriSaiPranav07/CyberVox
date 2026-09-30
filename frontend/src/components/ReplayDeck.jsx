import React, { useState, useEffect } from "react";
import { Play, Pause, Square, FastForward, Zap, ShieldAlert, Radio, Flame, Search, UploadCloud, Globe } from "lucide-react";
import { startReplay, pauseReplay, resumeReplay, stopReplay, fetchReplayStatus, triggerThreatScenario } from "../services/api";

export function ReplayDeck() {
  const [status, setStatus] = useState(null);
  const [speed, setSpeed] = useState(1.0);
  const [dataset, setDataset] = useState("synthetic_enterprise_traffic");
  const [injecting, setInjecting] = useState(null);

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const res = await fetchReplayStatus();
        setStatus(res);
      } catch (e) {}
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    const res = await startReplay({ dataset_name: dataset, speed_multiplier: speed });
    setStatus(res);
  };

  const handlePauseResume = async () => {
    if (status?.is_paused) {
      const res = await resumeReplay();
      setStatus(res);
    } else {
      const res = await pauseReplay();
      setStatus(res);
    }
  };

  const handleStop = async () => {
    const res = await stopReplay();
    setStatus(res);
  };

  const handleTrigger = async (scenario) => {
    setInjecting(scenario);
    try {
      await triggerThreatScenario(scenario);
    } catch (e) {}
    setTimeout(() => setInjecting(null), 800);
  };

  const scenarios = [
    { id: "DDOS", name: "SYN Flood Burst", icon: Flame, color: "#ef4444", desc: "Inject 60-packet SYN flood at 10.0.1.15" },
    { id: "C2", name: "Botnet C2 Beacon", icon: Radio, color: "#f59e0b", desc: "Inject 8 periodic robotic pulses (Cobalt Strike JA3)" },
    { id: "DGA", name: "Algorithmic DGA Queries", icon: Globe, color: "#3b82f6", desc: "Inject pseudo-random high-entropy domain lookups" },
    { id: "DNS_TUNNELLING", name: "DNS Exfiltration Chunk", icon: Zap, color: "#8b5cf6", desc: "Inject hex-encoded TXT record payload chunk" },
    { id: "PORT_SCAN", name: "Vertical Port Sweep", icon: Search, color: "#06b6d4", desc: "Inject 25 rapid TCP SYN port probes" },
    { id: "EXFILTRATION", name: "Data Exfiltration Burst", icon: UploadCloud, color: "#ec4899", desc: "Inject 3.2MB outbound asymmetric egress transfer" }
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "20px" }}>
      
      {/* Panel 1: PCAP & Stream Controller */}
      <div className="glass-panel" style={{ padding: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
          <div>
            <h2 style={{ fontSize: "1.0rem", fontWeight: 700, color: "#f8fafc" }}>
              PCAP REPLAY & INGESTION CONTROLLER
            </h2>
            <p style={{ fontSize: "0.74rem", color: "var(--text-muted)" }}>
              Stream replayed packet traces into the exact same passive intelligence pipeline
            </p>
          </div>
          <span style={{
            fontSize: "0.72rem",
            padding: "3px 8px",
            borderRadius: "4px",
            fontWeight: 700,
            background: status?.is_active ? (status?.is_paused ? "rgba(245, 158, 11, 0.2)" : "rgba(16, 185, 129, 0.2)") : "rgba(255, 255, 255, 0.05)",
            color: status?.is_active ? (status?.is_paused ? "#fbbf24" : "#34d399") : "var(--text-muted)",
            border: `1px solid ${status?.is_active ? (status?.is_paused ? "rgba(245, 158, 11, 0.4)" : "rgba(16, 185, 129, 0.4)") : "var(--border-subtle)"}`
          }}>
            {status?.is_active ? (status?.is_paused ? "PAUSED" : "STREAMING ACTIVE") : "IDLE"}
          </span>
        </div>

        {/* Dataset Selection */}
        <div style={{ marginBottom: "16px" }}>
          <label style={{ display: "block", fontSize: "0.72rem", color: "var(--text-secondary)", marginBottom: "6px", fontWeight: 600 }}>
            Select Replay Dataset / Stream Mode
          </label>
          <select
            value={dataset}
            onChange={(e) => setDataset(e.target.value)}
            disabled={status?.is_active}
            style={{
              width: "100%",
              background: "rgba(15, 23, 42, 0.8)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "6px",
              padding: "8px 12px",
              color: "#f8fafc",
              fontSize: "0.80rem",
              outline: "none"
            }}
          >
            <option value="synthetic_enterprise_traffic">Synthetic Enterprise Mirror Feed (Mixed Benign + Periodic Attacks)</option>
            <option value="pcap_mirror_stream">PCAP Libpcap Read-Only Binary Feed (Simulated Capture)</option>
            <option value="ctu13_botnet_trace">CTU-13 / CIC-IDS2017 Validated Traffic Trace</option>
          </select>
        </div>

        {/* Speed Multiplier */}
        <div style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.72rem", color: "var(--text-secondary)", marginBottom: "6px", fontWeight: 600 }}>
            <span>Replay Speed Multiplier</span>
            <span style={{ color: "#38bdf8", fontWeight: 700 }}>{speed}x</span>
          </div>
          <div style={{ display: "flex", gap: "6px" }}>
            {[0.5, 1.0, 2.0, 5.0, 10.0].map((s) => (
              <button
                key={s}
                onClick={() => setSpeed(s)}
                style={{
                  flex: 1,
                  background: speed === s ? "rgba(59, 130, 246, 0.25)" : "rgba(15, 23, 42, 0.6)",
                  border: speed === s ? "1px solid #38bdf8" : "1px solid var(--border-subtle)",
                  color: speed === s ? "#38bdf8" : "var(--text-secondary)",
                  padding: "6px",
                  borderRadius: "4px",
                  fontSize: "0.74rem",
                  fontWeight: 600,
                  cursor: "pointer"
                }}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>

        {/* Primary Controls */}
        <div style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
          {!status?.is_active ? (
            <button
              onClick={handleStart}
              style={{
                flex: 1,
                background: "linear-gradient(135deg, #06b6d4, #3b82f6)",
                border: "none",
                borderRadius: "6px",
                padding: "10px",
                color: "#ffffff",
                fontWeight: 700,
                fontSize: "0.82rem",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "6px",
                cursor: "pointer",
                boxShadow: "0 0 16px rgba(6, 182, 212, 0.3)"
              }}
            >
              <Play size={16} /> Start Passive Replay
            </button>
          ) : (
            <>
              <button
                onClick={handlePauseResume}
                style={{
                  flex: 1,
                  background: "rgba(245, 158, 11, 0.2)",
                  border: "1px solid rgba(245, 158, 11, 0.4)",
                  borderRadius: "6px",
                  padding: "10px",
                  color: "#fbbf24",
                  fontWeight: 700,
                  fontSize: "0.82rem",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "6px",
                  cursor: "pointer"
                }}
              >
                {status?.is_paused ? <Play size={16} /> : <Pause size={16} />}
                {status?.is_paused ? "Resume Replay" : "Pause Replay"}
              </button>

              <button
                onClick={handleStop}
                style={{
                  flex: 1,
                  background: "rgba(244, 63, 94, 0.2)",
                  border: "1px solid rgba(244, 63, 94, 0.4)",
                  borderRadius: "6px",
                  padding: "10px",
                  color: "#fb7185",
                  fontWeight: 700,
                  fontSize: "0.82rem",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "6px",
                  cursor: "pointer"
                }}
              >
                <Square size={16} /> Stop Replay
              </button>
            </>
          )}
        </div>

        {/* Live Replay Metrics */}
        <div style={{ background: "rgba(9, 14, 23, 0.6)", padding: "12px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px", textAlign: "center" }}>
            <div>
              <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>Processed</div>
              <div style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc" }}>
                {(status?.processed_records || 0).toLocaleString()}
              </div>
            </div>
            <div>
              <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>Current FPS</div>
              <div style={{ fontSize: "0.95rem", fontWeight: 700, color: "#38bdf8" }}>
                {status?.current_rate_fps || 0}
              </div>
            </div>
            <div>
              <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>Alerts Fired</div>
              <div style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f43f5e" }}>
                {status?.alerts_generated || 0}
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* Panel 2: Live Threat Injection Deck for SIH Demonstration */}
      <div className="glass-panel" style={{ padding: "20px" }}>
        <div style={{ marginBottom: "14px" }}>
          <h2 style={{ fontSize: "1.0rem", fontWeight: 700, color: "#f8fafc" }}>
            SIH LIVE ATTACK DEMONSTRATION DECK
          </h2>
          <p style={{ fontSize: "0.74rem", color: "var(--text-muted)" }}>
            Inject standalone attack scenario bursts directly into the pipeline to observe immediate real-time detection
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
          {scenarios.map((sc) => {
            const Icon = sc.icon;
            const isCurrent = injecting === sc.id;
            return (
              <button
                key={sc.id}
                onClick={() => handleTrigger(sc.id)}
                style={{
                  background: isCurrent ? `${sc.color}30` : "rgba(15, 23, 42, 0.6)",
                  border: `1px solid ${isCurrent ? sc.color : "var(--border-subtle)"}`,
                  borderRadius: "8px",
                  padding: "12px",
                  textAlign: "left",
                  cursor: "pointer",
                  transition: "all 0.15s ease"
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                  <Icon size={14} color={sc.color} />
                  <span style={{ fontSize: "0.76rem", fontWeight: 700, color: "#f1f5f9" }}>
                    {sc.name}
                  </span>
                </div>
                <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", lineHeight: "1.3" }}>
                  {sc.desc}
                </div>
              </button>
            );
          })}
        </div>

        <div style={{
          marginTop: "16px",
          padding: "10px",
          borderRadius: "6px",
          background: "rgba(59, 130, 246, 0.08)",
          border: "1px solid rgba(59, 130, 246, 0.2)",
          fontSize: "0.70rem",
          color: "#93c5fd"
        }}>
          <strong>Note for Judges:</strong> All attacks are simulated in-memory flow metadata. Zero packets are emitted onto your actual physical network.
        </div>
      </div>

    </div>
  );
}
