import React from "react";
import { Radio, Play, Pause, Square, Layers, Cpu, Server, Zap, RefreshCw } from "lucide-react";

export function TrafficSourceSelector({
  trafficMode,
  onSelectMode,
  replayStatus,
  onStartReplay,
  onPauseResumeReplay,
  onStopReplay,
  onTriggerBurst
}) {
  const modes = [
    {
      id: "PCAP_REPLAY",
      title: "PCAP REPLAY",
      badge: "Binary Libpcap Feed",
      desc: "Replaying sanitized packet traces into passive streaming pipeline",
      icon: Layers,
      color: "#06b6d4"
    },
    {
      id: "SYNTHETIC_DEMO",
      title: "SYNTHETIC DEMO",
      badge: "Controlled Simulation",
      desc: "Safe local flow generation simulating enterprise & multi-stage attacks",
      icon: Cpu,
      color: "#8b5cf6"
    },
    {
      id: "PASSIVE_LIVE_FEED",
      title: "PASSIVE LIVE FEED",
      badge: "Architecture Ready",
      desc: "Ready for physical optical tap mirror (Zero return path enforced)",
      icon: Server,
      color: "#10b981"
    }
  ];

  const currentModeInfo = modes.find((m) => m.id === trafficMode) || modes[1];

  return (
    <div className="glass-panel" style={{ padding: "16px 20px", marginBottom: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
        
        {/* Left: Prominent Traffic Source Indicator Badge */}
        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
          <div>
            <div style={{ fontSize: "0.68rem", fontWeight: 800, letterSpacing: "0.08em", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "2px" }}>
              TRAFFIC SOURCE
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: replayStatus?.is_active ? "#10b981" : "#06b6d4",
                  boxShadow: replayStatus?.is_active ? "0 0 10px #10b981" : "0 0 8px #06b6d4"
                }}
                className={replayStatus?.is_active ? "pulse-emerald" : ""}
              />
              <span style={{ fontSize: "1.05rem", fontWeight: 800, color: "#f8fafc", letterSpacing: "-0.01em" }}>
                ● {currentModeInfo.title}
              </span>
              <span
                style={{
                  fontSize: "0.68rem",
                  padding: "2px 8px",
                  background: "rgba(59, 130, 246, 0.15)",
                  color: "#60a5fa",
                  borderRadius: "4px",
                  fontWeight: 600,
                  border: "1px solid rgba(59, 130, 246, 0.3)"
                }}
              >
                {currentModeInfo.badge}
              </span>
            </div>
          </div>
        </div>

        {/* Center: Mode Switching Buttons */}
        <div style={{ display: "flex", gap: "6px", background: "rgba(15, 23, 42, 0.6)", padding: "4px", borderRadius: "8px", border: "1px solid var(--border-subtle)" }}>
          {modes.map((m) => {
            const isSelected = trafficMode === m.id;
            return (
              <button
                key={m.id}
                onClick={() => onSelectMode(m.id)}
                style={{
                  background: isSelected ? "rgba(59, 130, 246, 0.25)" : "transparent",
                  border: isSelected ? "1px solid #38bdf8" : "1px solid transparent",
                  color: isSelected ? "#38bdf8" : "var(--text-secondary)",
                  padding: "6px 12px",
                  borderRadius: "6px",
                  fontSize: "0.74rem",
                  fontWeight: 700,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  transition: "all 0.15s ease"
                }}
              >
                <m.icon size={13} color={isSelected ? "#38bdf8" : "var(--text-muted)"} />
                {m.title}
              </button>
            );
          })}
        </div>

        {/* Right: Instant Play / Pause / Scenario Quick Deck */}
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {!replayStatus?.is_active ? (
            <button
              onClick={onStartReplay}
              style={{
                background: "linear-gradient(135deg, #06b6d4, #3b82f6)",
                border: "none",
                borderRadius: "6px",
                padding: "8px 14px",
                color: "#ffffff",
                fontWeight: 700,
                fontSize: "0.78rem",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                cursor: "pointer",
                boxShadow: "0 0 12px rgba(6, 182, 212, 0.35)"
              }}
            >
              <Play size={14} /> Start Traffic Stream
            </button>
          ) : (
            <>
              <button
                onClick={onPauseResumeReplay}
                style={{
                  background: "rgba(245, 158, 11, 0.2)",
                  border: "1px solid rgba(245, 158, 11, 0.4)",
                  borderRadius: "6px",
                  padding: "8px 12px",
                  color: "#fbbf24",
                  fontWeight: 700,
                  fontSize: "0.76rem",
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                  cursor: "pointer"
                }}
              >
                {replayStatus?.is_paused ? <Play size={13} /> : <Pause size={13} />}
                {replayStatus?.is_paused ? "Resume" : "Pause"}
              </button>
              <button
                onClick={onStopReplay}
                style={{
                  background: "rgba(244, 63, 94, 0.2)",
                  border: "1px solid rgba(244, 63, 94, 0.4)",
                  borderRadius: "6px",
                  padding: "8px 12px",
                  color: "#fb7185",
                  fontWeight: 700,
                  fontSize: "0.76rem",
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                  cursor: "pointer"
                }}
              >
                <Square size={13} /> Stop
              </button>
            </>
          )}

          {/* Quick Scenario Injectors */}
          <button
            onClick={() => onTriggerBurst("DDOS")}
            title="Inject SYN Flood Attack Burst"
            style={{
              background: "rgba(239, 68, 68, 0.15)",
              border: "1px solid rgba(239, 68, 68, 0.35)",
              color: "#f87171",
              padding: "8px 10px",
              borderRadius: "6px",
              fontSize: "0.72rem",
              fontWeight: 700,
              cursor: "pointer"
            }}
          >
            + SYN Flood
          </button>
          <button
            onClick={() => onTriggerBurst("C2")}
            title="Inject C2 Periodic Beaconing"
            style={{
              background: "rgba(245, 158, 11, 0.15)",
              border: "1px solid rgba(245, 158, 11, 0.35)",
              color: "#fbbf24",
              padding: "8px 10px",
              borderRadius: "6px",
              fontSize: "0.72rem",
              fontWeight: 700,
              cursor: "pointer"
            }}
          >
            + C2 Beacon
          </button>
        </div>

      </div>
    </div>
  );
}
