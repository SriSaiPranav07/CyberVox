/**
 * SIH 2026 REST API Client
 */

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000/api";

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchStatistics() {
  const res = await fetch(`${API_BASE}/statistics`);
  return res.json();
}

export async function fetchThreats() {
  const res = await fetch(`${API_BASE}/threats`);
  return res.json();
}

export async function fetchAlerts(limit = 100, severity = "", category = "") {
  const params = new URLSearchParams();
  if (limit) params.append("limit", limit);
  if (severity && severity !== "ALL") params.append("severity", severity);
  if (category && category !== "ALL") params.append("category", category);
  
  const res = await fetch(`${API_BASE}/alerts?${params.toString()}`);
  return res.json();
}

export async function fetchRecentFlows(limit = 30) {
  const res = await fetch(`${API_BASE}/flows?limit=${limit}`);
  return res.json();
}

export async function setTrafficMode(mode) {
  const res = await fetch(`${API_BASE}/traffic/mode/${mode}`, { method: "POST" });
  return res.json();
}

export async function startReplay(config) {
  const res = await fetch(`${API_BASE}/replay/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config || { dataset_name: "synthetic_enterprise_traffic", speed_multiplier: 1.0, traffic_mode: "SYNTHETIC_DEMO" })
  });
  return res.json();
}

export async function pauseReplay() {
  const res = await fetch(`${API_BASE}/replay/pause`, { method: "POST" });
  return res.json();
}

export async function resumeReplay() {
  const res = await fetch(`${API_BASE}/replay/resume`, { method: "POST" });
  return res.json();
}

export async function stopReplay() {
  const res = await fetch(`${API_BASE}/replay/stop`, { method: "POST" });
  return res.json();
}

export async function fetchReplayStatus() {
  const res = await fetch(`${API_BASE}/replay/status`);
  return res.json();
}

export async function triggerThreatScenario(scenarioName) {
  const res = await fetch(`${API_BASE}/replay/scenario/${scenarioName}`, { method: "POST" });
  return res.json();
}

export async function runBenchmark(params) {
  const res = await fetch(`${API_BASE}/benchmark`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params || { total_flows: 5000, target_rate: 2000, threat_ratio: 0.15 })
  });
  return res.json();
}

export async function fetchModels() {
  const res = await fetch(`${API_BASE}/models`);
  return res.json();
}

export async function resetSystem() {
  const res = await fetch(`${API_BASE}/reset`, { method: "POST" });
  return res.json();
}
