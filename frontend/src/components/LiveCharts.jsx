import React, { useEffect, useState } from "react";
import { TrendingUp, Clock, ShieldCheck } from "lucide-react";

export function LiveCharts({ metrics, alerts }) {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    if (!metrics) return;
    setHistory((prev) => {
      const point = {
        time: new Date().toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        fps: metrics.flows_per_sec || 0,
        pps: metrics.packets_per_sec || 0,
        lat: metrics.avg_processing_latency_ms || 0
      };
      const next = [...prev, point];
      return next.slice(-20); // Keep last 20 ticks
    });
  }, [metrics]);

  // Compute SVG polyline points for Throughput chart
  const maxFps = Math.max(100, ...history.map((h) => h.fps));
  const maxLat = Math.max(1.0, ...history.map((h) => h.lat));

  const width = 450;
  const height = 120;
  const padding = 20;

  const fpsPoints = history
    .map((h, i) => {
      const x = padding + (i / Math.max(1, history.length - 1)) * (width - 2 * padding);
      const y = height - padding - (h.fps / maxFps) * (height - 2 * padding);
      return `${x},${y}`;
    })
    .join(" ");

  const latPoints = history
    .map((h, i) => {
      const x = padding + (i / Math.max(1, history.length - 1)) * (width - 2 * padding);
      const y = height - padding - (h.lat / maxLat) * (height - 2 * padding);
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: "16px", marginBottom: "20px" }}>
      
      {/* Chart 1: Real-Time Traffic Ingestion Rate */}
      <div className="glass-panel" style={{ padding: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <TrendingUp size={16} color="#06b6d4" />
            <h3 style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
              STREAMING INGESTION VELOCITY
            </h3>
          </div>
          <span style={{ fontSize: "0.72rem", color: "#06b6d4", fontWeight: 700 }}>
            {metrics?.flows_per_sec || 0} flows/s
          </span>
        </div>

        <div style={{ width: "100%", height: "130px", background: "rgba(9, 14, 23, 0.6)", borderRadius: "6px", overflow: "hidden", position: "relative" }}>
          <svg viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "100%" }}>
            <defs>
              <linearGradient id="cyanGlow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
              </linearGradient>
            </defs>
            {/* Grid lines */}
            <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
            <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
            <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="rgba(255,255,255,0.05)" />

            {history.length > 1 && (
              <>
                <polygon
                  points={`${padding},${height - padding} ${fpsPoints} ${width - padding},${height - padding}`}
                  fill="url(#cyanGlow)"
                />
                <polyline
                  fill="none"
                  stroke="#06b6d4"
                  strokeWidth="2.5"
                  points={fpsPoints}
                />
              </>
            )}
          </svg>
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: "6px", fontSize: "0.68rem", color: "var(--text-muted)" }}>
          <span>Past 20 seconds</span>
          <span>Peak: {Math.round(maxFps)} FPS</span>
        </div>
      </div>

      {/* Chart 2: Pipeline Processing Latency Timeline */}
      <div className="glass-panel" style={{ padding: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Clock size={16} color="#10b981" />
            <h3 style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
              PIPELINE DETECTION LATENCY
            </h3>
          </div>
          <span style={{ fontSize: "0.72rem", color: "#10b981", fontWeight: 700 }}>
            {(metrics?.avg_processing_latency_ms || 0).toFixed(3)} ms
          </span>
        </div>

        <div style={{ width: "100%", height: "130px", background: "rgba(9, 14, 23, 0.6)", borderRadius: "6px", overflow: "hidden", position: "relative" }}>
          <svg viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "100%" }}>
            <defs>
              <linearGradient id="greenGlow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10b981" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
              </linearGradient>
            </defs>
            <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
            <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
            <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="rgba(255,255,255,0.05)" />

            {history.length > 1 && (
              <>
                <polygon
                  points={`${padding},${height - padding} ${latPoints} ${width - padding},${height - padding}`}
                  fill="url(#greenGlow)"
                />
                <polyline
                  fill="none"
                  stroke="#10b981"
                  strokeWidth="2.5"
                  points={latPoints}
                />
              </>
            )}
          </svg>
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: "6px", fontSize: "0.68rem", color: "var(--text-muted)" }}>
          <span>Ingest &rarr; Features &rarr; Inference &rarr; Alert</span>
          <span>P95: {(metrics?.p95_processing_latency_ms || 0).toFixed(3)} ms</span>
        </div>
      </div>

    </div>
  );
}
