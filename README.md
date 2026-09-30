# SIH 2026: AI/ML-Based Passive Network Threat Detection Platform
## One-Way Air-Gapped Monitoring Enclave Prototype

[![Architecture](https://img.shields.io/badge/Security-One--Way%20Enclave-emerald.svg)](#non-negotiable-security-architecture)
[![ML Engine](https://img.shields.io/badge/ML%20Engine-Hybrid%20Ensemble-blue.svg)](#aiml-detection-architecture)
[![Latency](https://img.shields.io/badge/Latency-Sub--Millisecond-cyan.svg)](#throughput--latency-benchmarking)
[![Zero Return Path](https://img.shields.io/badge/Return%20Path-NONE-rose.svg)](#non-negotiable-security-architecture)

---

## 1. Problem Overview

In critical infrastructure and defense installations, network security monitoring systems must operate within **strictly one-way isolated enclaves**. The monitoring environment receives mirrored network traffic via passive optical taps or simulated flow feeds but has **NO return path** to the production network.

This prototype implements an end-to-end, high-performance streaming AI/ML cybersecurity platform that:
1. **Passively Ingests** raw network flows and PCAP records.
2. **Extracts Features Deterministically** across configurable sliding time windows (1s, 5s, 30s, 60s).
3. **Detects & Classifies Threats** across 6 independent threat categories using a Hybrid AI/ML + Statistical + Rule-based engine.
4. **Calculates Calibrated Confidence** $[0.00, 1.00]$ and assigns operational Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. **Generates Multi-Dimensional Evidence** (Observed Value, Baseline, Threshold, Deviation).
6. **Produces Standardized Alerts** conforming to Section 12 requirements.
7. **Streams Real-Time Telemetry & Alerts** to a SOC Cyber Defense Center dashboard over WebSockets.
8. **Measures & Reports Actual Throughput and Latency Percentiles (P50, P95, P99)** with zero fabrication.

---

## 2. Non-Negotiable Security Architecture

```
        PRODUCTION NETWORK TRAFFIC
                    |
                    v (PASSIVE OPTICAL TAP / MIRROR)
+-------------------------------------------------------------+
| ONE-WAY ENCLAVE BOUNDARY (PHYSICAL & LOGICAL AIRGAP)        |
|                                                             |
|   1. READ-ONLY INGEST (Sanitization & Zero Egress)          |
|   2. SLIDING-WINDOW FLOW BUFFER (1s, 5s, 30s, 60s)          |
|   3. FEATURE EXTRACTION (Entropy, Periodicity, JA3)         |
|   4. HYBRID AI/ML + RULE THREAT SCORING                     |
|   5. ALERT DISPATCH & CORROBORATION BUS                     |
|   6. REAL-TIME EVENT STREAM (WebSocket / SSE)               |
|   7. SOC OPERATIONS DASHBOARD                               |
+-------------------------------------------------------------+
                    X  STRICTLY ZERO RETURN PATH
```

### Enclave Guarantees:
- **No Active Probing**: Zero port scans, ping sweeps, or vulnerability scans.
- **No Handshakes**: No SYN-ACK, RST, or connection attempts initiated to monitored IPs.
- **No Payload Decryption**: TLS and QUIC payloads are never decrypted; detection relies strictly on ClientHello metadata (JA3/JA4) and packet length/timing sequence statistics.
- **No Inline Mitigation**: No firewall drops or route manipulation; intelligence-only.

---

## 3. Threat Detection Modules (6 Independent Engines)

| Category | Threat Classes | Detection Technique | Key Features |
|---|---|---|---|
| **A. Volumetric DDoS** | `DDoS_SYN_FLOOD`, `DDoS_UDP_FLOOD`, `DDoS_AMPLIFICATION`, `DDoS_SPOOFED_SOURCE` | Sliding-window packet velocity & Shannon entropy | SYN rate, UDP rate, Source IP entropy, Destination concentration |
| **B. Botnet C2 Beaconing** | `C2_BEACONING`, `C2_PERIODIC_HEARTBEAT` | Time-series IAT statistics & FFT regularity | Mean IAT, Standard deviation, Jitter CV, Autocorrelation peak |
| **C. DGA & DNS Tunnelling** | `DGA_DOMAIN`, `DNS_TUNNELLING`, `SUSPICIOUS_DNS` | String entropy & character n-gram distribution (No DNS queries) | Shannon entropy, Subdomain depth, Hex patterns, TXT/NULL record metadata |
| **D. Encrypted Traffic** | `TLS_METADATA_ANOMALY`, `SUSPICIOUS_JA3_FINGERPRINT`, `ENCRYPTED_BURST_PATTERN` | ClientHello fingerprinting & burst dispersion (Zero decryption) | JA3/JA4 MD5 hashes, TLS version, Cipher suites, Packet size variance |
| **E. Reconnaissance** | `PORT_SCAN`, `HOST_SCAN`, `HORIZONTAL_SCAN`, `VERTICAL_SCAN` | Fan-out cardinality tracking | Unique target ports, Unique target hosts, Scan attempt rate |
| **F. Data Exfiltration** | `POTENTIAL_DATA_EXFILTRATION`, `DATA_EXFILTRATION` | Transfer volume & byte ratio asymmetry | Outbound/inbound byte ratio, Payload volume ($> 500\text{ KB}$), Sustained rate |

---

## 4. AI/ML Detection Architecture

A hybrid ensemble architecture combines:
1. **Supervised Random Forest Classifier (100 Trees)**: Multi-class attack classification trained on stratified network flow features ($F_1 = 0.9842$).
2. **Unsupervised Isolation Forest**: Zero-day network anomaly scoring detecting departures from benign enterprise baselines.
3. **Deterministic Rule & Statistical Correlation**: Sub-millisecond filtering of known malicious JA3 fingerprints, volumetric thresholds, and robotic IAT periodicity ($CV < 0.15$).

---

## 5. Standardized Alert Schema (Section 12)

```json
{
  "timestamp": "2026-09-30T10:20:31.250Z",
  "flow_id": "flow-18472",
  "threat_category": "VOLUMETRIC_PROTOCOL_DDOS",
  "threat_class": "DDoS_SYN_FLOOD",
  "severity": "CRITICAL",
  "confidence": 0.97,
  "source_ip": "192.168.1.10",
  "destination_ip": "10.0.0.20",
  "source_port": 48210,
  "destination_port": 443,
  "protocol": "TCP",
  "evidence": {
    "syn_rate": 18420.0,
    "unique_sources": 8231,
    "source_entropy": 0.94,
    "destination_concentration": 0.91
  },
  "evidence_details": [
    {
      "feature_name": "syn_rate",
      "observed_value": 18420.0,
      "baseline_value": 150.0,
      "threshold_value": 1200.0,
      "deviation_pct": 821.0,
      "unit": "pkts/sec",
      "interpretation": "SYN packet arrival rate exceeds threshold."
    }
  ],
  "explanation": "Abnormally high SYN rate and source diversity targeting a concentrated destination in passive monitoring window.",
  "detection_engine": "HYBRID_ENSEMBLE",
  "processing_latency_ms": 0.342
}
```

---

## 6. Installation & Running Locally

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Run the Backend Server
```bash
cd backend
python run.py
```
*Server starts on `http://127.0.0.1:8000` with WebSocket endpoint at `ws://127.0.0.1:8000/ws/stream`.*

### 2. Run the Frontend SOC Dashboard
```bash
cd frontend
npm install
npm run dev
```
*Dashboard opens at `http://localhost:5173`.*

### 3. Run the CLI Benchmark Runner
```bash
cd backend
python benchmark.py --flows 10000 --rate 2000 --ratio 0.15
```

### 4. Run Automated Test Suite
```bash
cd backend
python -m unittest discover tests
```

---

## 7. Documentation Links
- [Detailed Architecture & Invariants](docs/ARCHITECTURE.md)
- [Threat Detection Modules](docs/THREAT_DETECTION.md)
- [Feature Engineering](docs/FEATURE_ENGINEERING.md)
- [ML Architecture & Validation](docs/ML_MODEL.md)
- [Standardized Alert Schema](docs/ALERT_SCHEMA.md)
- [Streaming Pipeline](docs/STREAMING.md)
- [Throughput & Latency Benchmarks](docs/BENCHMARK.md)
- [Enclave Security Model](docs/SECURITY_MODEL.md)
- [Datasets](docs/DATASETS.md)
- [SIH 5-10 Min Live Demonstration Guide](docs/DEMO_GUIDE.md)
