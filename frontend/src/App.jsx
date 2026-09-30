import React, { useState, useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { TrafficSourceSelector } from "./components/TrafficSourceSelector";
import { MetricCards } from "./components/MetricCards";
import { NetworkTrafficOverview } from "./components/NetworkTrafficOverview";
import { ThreatEngineCards } from "./components/ThreatEngineCards";
import { LiveCharts } from "./components/LiveCharts";
import { AlertFeed } from "./components/AlertFeed";
import { ThreatTimeline } from "./components/ThreatTimeline";
import { ExplainableEvidencePanel } from "./components/ExplainableEvidencePanel";
import { SystemHealthPanel } from "./components/SystemHealthPanel";
import { ReplayDeck } from "./components/ReplayDeck";
import { BenchmarkPanel } from "./components/BenchmarkPanel";
import { DeepInspector } from "./components/DeepInspector";
import { SecurityAuditor } from "./components/SecurityAuditor";
import { socWebSocket } from "./services/websocket";
import {
  fetchHealth,
  fetchStatistics,
  fetchThreats,
  fetchAlerts,
  setTrafficMode,
  startReplay,
  pauseReplay,
  resumeReplay,
  stopReplay,
  fetchReplayStatus,
  triggerThreatScenario,
  resetSystem
} from "./services/api";

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [trafficMode, setTrafficModeState] = useState("SYNTHETIC_DEMO");
  const [replayStatus, setReplayStatus] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [activeCategoryFilter, setActiveCategoryFilter] = useState(null);
  const [enclaveStatus, setEnclaveStatus] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  // Initial load & WebSocket connection
  useEffect(() => {
    const loadInitial = async () => {
      try {
        const health = await fetchHealth();
        setEnclaveStatus(health.enclave_security);
        const st = await fetchStatistics();
        setMetrics(st);
        if (st.traffic_mode) setTrafficModeState(st.traffic_mode);
        const th = await fetchThreats();
        setStats(th);
        const al = await fetchAlerts(50);
        setAlerts(al || []);
        if (al && al.length > 0) setSelectedAlert(al[0]);
        const rep = await fetchReplayStatus();
        setReplayStatus(rep);
      } catch (e) {
        console.error("Initial load failed", e);
      }
    };
    loadInitial();

    socWebSocket.connect();
    const unsubscribe = socWebSocket.subscribe((msg) => {
      if (msg.type === "CONNECTION_STATUS") {
        setWsConnected(msg.status === "CONNECTED");
      } else if (msg.type === "INIT") {
        setMetrics(msg.metrics);
        setStats(msg.stats);
        setAlerts(msg.alerts || []);
        if (msg.alerts && msg.alerts.length > 0 && !selectedAlert) {
          setSelectedAlert(msg.alerts[0]);
        }
      } else if (msg.type === "METRICS_TICK") {
        setMetrics(msg.metrics);
        setStats(msg.stats);
      } else if (msg.type === "NEW_ALERT") {
        setAlerts((prev) => [msg.data, ...prev].slice(0, 500));
        setSelectedAlert(msg.data); // Automatically highlight newest threat
      }
    });

    const interval = setInterval(async () => {
      try {
        const rep = await fetchReplayStatus();
        setReplayStatus(rep);
      } catch (e) {}
    }, 1500);

    return () => {
      unsubscribe();
      clearInterval(interval);
      socWebSocket.disconnect();
    };
  }, []);

  const handleModeChange = async (mode) => {
    setTrafficModeState(mode);
    await setTrafficMode(mode);
  };

  const handleStartReplay = async () => {
    const res = await startReplay({
      dataset_name: trafficMode === "PCAP_REPLAY" ? "pcap_mirror_stream" : "synthetic_enterprise_traffic",
      speed_multiplier: 1.0,
      traffic_mode: trafficMode
    });
    setReplayStatus(res);
  };

  const handlePauseResumeReplay = async () => {
    if (replayStatus?.is_paused) {
      const res = await resumeReplay();
      setReplayStatus(res);
    } else {
      const res = await pauseReplay();
      setReplayStatus(res);
    }
  };

  const handleStopReplay = async () => {
    const res = await stopReplay();
    setReplayStatus(res);
  };

  const handleTriggerBurst = async (scenario) => {
    await triggerThreatScenario(scenario);
  };

  const handleReset = async () => {
    await resetSystem();
    const st = await fetchStatistics();
    setMetrics(st);
    const th = await fetchThreats();
    setStats(th);
    setAlerts([]);
    setSelectedAlert(null);
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Navigation & Enclave Status Header */}
      <Navbar
        enclaveStatus={enclaveStatus}
        wsConnected={wsConnected}
        onReset={handleReset}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* Main Container */}
      <main style={{ flex: 1, padding: "20px 24px", maxWidth: "1650px", margin: "0 auto", width: "100%" }}>
        
        {activeTab === "dashboard" && (
          <>
            {/* 1. Prominent Traffic Source Selector & Stream Controls */}
            <TrafficSourceSelector
              trafficMode={trafficMode}
              onSelectMode={handleModeChange}
              replayStatus={replayStatus}
              onStartReplay={handleStartReplay}
              onPauseResumeReplay={handlePauseResumeReplay}
              onStopReplay={handleStopReplay}
              onTriggerBurst={handleTriggerBurst}
            />

            {/* 2. Key Metric Cards */}
            <MetricCards metrics={metrics} stats={stats} />

            {/* 3. Live Ingestion & Sub-millisecond Latency Charts */}
            <LiveCharts metrics={metrics} alerts={alerts} />

            {/* 4. Network Traffic Analytics (Top Sources, Top Destinations, Top Ports) */}
            <NetworkTrafficOverview metrics={metrics} />

            {/* 5. Six Independent Threat Engine Cards */}
            <ThreatEngineCards
              stats={stats}
              onSelectCategory={(cat) => setActiveCategoryFilter(cat === activeCategoryFilter ? null : cat)}
              activeCategory={activeCategoryFilter}
            />

            {/* 6. Two-Column Core: Live Alerts Stream & Threat Timeline */}
            <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: "20px", marginBottom: "20px" }}>
              <AlertFeed
                alerts={alerts}
                onSelectAlert={(a) => setSelectedAlert(a)}
                selectedAlert={selectedAlert}
                activeCategoryFilter={activeCategoryFilter}
                setActiveCategoryFilter={setActiveCategoryFilter}
              />
              <ThreatTimeline
                alerts={alerts}
                onSelectAlert={(a) => setSelectedAlert(a)}
                selectedAlert={selectedAlert}
              />
            </div>

            {/* 7. Selected Alert / Explainable Evidence Panel */}
            <ExplainableEvidencePanel alert={selectedAlert} />

            {/* 8. System Health Diagnostics & Subsystem Status */}
            <SystemHealthPanel metrics={metrics} wsConnected={wsConnected} />
          </>
        )}

        {activeTab === "replay" && (
          <>
            <ReplayDeck />
            <AlertFeed
              alerts={alerts}
              onSelectAlert={(a) => setSelectedAlert(a)}
              selectedAlert={selectedAlert}
              activeCategoryFilter={activeCategoryFilter}
              setActiveCategoryFilter={setActiveCategoryFilter}
            />
          </>
        )}

        {activeTab === "benchmark" && (
          <BenchmarkPanel />
        )}

        {activeTab === "deep-inspector" && (
          <DeepInspector />
        )}

        {activeTab === "enclave-audit" && (
          <SecurityAuditor enclaveStatus={enclaveStatus} />
        )}

      </main>

      {/* SOC Footer */}
      <footer style={{
        borderTop: "1px solid var(--border-subtle)",
        padding: "12px 24px",
        background: "rgba(11, 15, 25, 0.95)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        fontSize: "0.72rem",
        color: "var(--text-muted)",
        flexWrap: "wrap",
        gap: "10px"
      }}>
        <div>
          SIH 2026 AI/ML Passive Network Threat Intelligence Enclave v2.0 | Intelligence-Only Airgap
        </div>
        <div style={{ display: "flex", gap: "16px" }}>
          <span>Airgap Integrity: <strong style={{ color: "#34d399" }}>100% ONE-WAY</strong></span>
          <span>Return Path: <strong style={{ color: "#fb7185" }}>NONE</strong></span>
          <span>Payload Decryption: <strong style={{ color: "#fbbf24" }}>DISABLED (METADATA ONLY)</strong></span>
        </div>
      </footer>
    </div>
  );
}
