# Non-Negotiable System Architecture & One-Way Enclave Model

## 1. System Overview

The **SIH 2026 AI/ML Passive Network Threat Intelligence Enclave** is designed for high-security, air-gapped monitoring enclaves operating under a strict **One-Way Data Diode / Optical Tap** model.

The platform receives passive mirrored IP packet streams and NetFlow/IPFIX records, extracts multi-dimensional network features across sliding time windows, executes hybrid threat detection (Rules + Statistical Anomaly + ML Classifiers), and streams structured alerts to a security operations dashboard.

```
       NETWORK TRAFFIC (PRODUCTION)
                   |
                   v (PASSIVE OPTICAL TAP / MIRROR)
+-------------------------------------------------------------+
| ONE-WAY ENCLAVE BOUNDARY (PHYSICAL / LOGICAL AIRGAP)        |
|                                                             |
|   1. READ-ONLY INGEST LAYER (Sanitization & Zero Egress)   |
|                  |                                          |
|                  v                                          |
|   2. SLIDING-WINDOW FLOW ACCUMULATOR (1s, 5s, 30s, 60s)     |
|                  |                                          |
|                  v                                          |
|   3. DETERMINISTIC FEATURE EXTRACTION ENGINE                |
|      - Shannon Entropy (Source/Dest IP, Ports, DNS)         |
|      - Inter-Arrival Time (IAT) & FFT Jitter Cadence        |
|      - TLS JA3/JA4 ClientHello Fingerprints                 |
|      - Fan-Out & Outbound/Inbound Asymmetry                 |
|                  |                                          |
|                  v                                          |
|   4. HYBRID AI/ML THREAT DETECTION & SCORING ENGINE        |
|      +-----------------+-----------------+---------------+  |
|      | Rule Engine     | Statistical     | ML Models     |  |
|      | (JA3, Scans)    | (Entropy, FFT)  | (RF, I-Forest)|  |
|      +-----------------+-----------------+---------------+  |
|                  |                                          |
|                  v                                          |
|   5. STANDARDIZED ALERT DISPATCH & CORROBORATION BUS        |
|                  |                                          |
|                  v                                          |
|   6. REAL-TIME EVENT STREAM (WebSocket / SSE)               |
|                  |                                          |
|                  v                                          |
|   7. SOC CYBER DEFENSE DASHBOARD                            |
+-------------------------------------------------------------+
                   X  STRICTLY ZERO RETURN PATH
```

---

## 2. Non-Negotiable Enclave Invariants

The monitoring enclave strictly forbids any interactive or outbound communications:
1. **Zero Return Path**: No TCP connections, SYN-ACKs, RST packets, or ICMP messages are ever emitted to monitored production hosts.
2. **Zero Active Probing**: No port scanning, host discovery, or vulnerability scanning is initiated.
3. **Zero Payload Decryption**: Encrypted TLS/QUIC streams are analyzed strictly via header/handshake metadata (JA3/JA4, cipher suites, packet length distributions, and timing sequences).
4. **No Inline Mitigation**: The system produces intelligence and alerts only. It does not manipulate network routes, inject drop rules, or quarantine hosts directly on the monitored network.
5. **No External DNS Resolution**: Suspicious DGA domains and DNS tunnelling payload labels are analyzed purely in-memory using Shannon entropy and n-gram perplexity.

---

## 3. Component Breakdown

| Layer | Component | File Path | Responsibility |
|---|---|---|---|
| **Ingest** | `ReadOnlyIngestValidator` | `backend/app/core/ingest.py` | Schema validation, IP regex sanity, zero-egress enforcement |
| **Parser** | `PassivePCAPParser` | `backend/app/core/pcap_parser.py` | Binary libpcap & PCAPNG stream decoder |
| **Aggregator** | `SlidingWindowFlowAggregator` | `backend/app/core/flow_aggregator.py` | Ring-buffered temporal window management (1s-60s) |
| **Features** | `FeatureExtractor` | `backend/app/core/feature_extractor.py` | Shannon entropy, IAT periodicity, JA3 calculation |
| **Detection** | `HybridDetectionEngine` | `backend/app/detection/hybrid_engine.py` | Multi-category scoring, confidence calculation, alert generation |
| **ML Engine** | `ThreatMLManager` | `backend/app/ml/model_manager.py` | Random Forest & Isolation Forest inference |
| **Streaming** | `StreamingDetectionPipeline`| `backend/app/core/pipeline.py` | Throughput tracking, sub-millisecond latency measurement |
| **Dashboard** | SOC Defense Center UI | `frontend/src/` | Real-time WebSocket visualizer, alert inspector, replay deck |
