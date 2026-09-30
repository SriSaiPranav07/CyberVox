# SIH 2026 Live Demonstration Guide (5–10 Minutes)

This guide provides the recommended sequence for presenting the prototype to SIH judges.

---

## Step 1: Open the SOC Operations Dashboard (0:00 - 1:00)
1. Open browser at `http://localhost:5173`.
2. Direct the judges' attention to the top status badges:
   - `PASSIVE MONITORING: ACTIVE`
   - `READ-ONLY INGEST: ACTIVE`
   - `RETURN PATH: NONE (PHYSICAL/LOGICAL ONE-WAY AIRGAP)`
   - `PAYLOAD DECRYPTION: DISABLED (METADATA ONLY)`
3. Explain that the enclave is **strictly intelligence-only** and never contacts the monitored network.

---

## Step 2: Start Traffic Replay (1:00 - 2:30)
1. Switch to the **PCAP & Attack Simulation** tab.
2. Click **Start Passive Replay** (Speed: 1x or 2x).
3. Switch back to **SOC Live Operations**:
   - Point out live **Flows/sec**, **Packets/sec**, and **Bandwidth (Mbps)** streaming in real time.
   - Observe the live SVG ingestion velocity and sub-millisecond latency timeline charts.

---

## Step 3: Demonstrate Attack Category Detections (2:30 - 6:00)
From the **PCAP & Attack Simulation** control deck, trigger each threat scenario:
1. **DDoS SYN Flood**: Click `[+ SYN Flood Burst]`.
   - Live alert `DDoS_SYN_FLOOD` fires immediately with CRITICAL severity.
2. **Botnet C2 Beaconing**: Click `[+ Botnet C2 Beacon]`.
   - Alert `C2_BEACONING` fires showing low jitter $CV < 0.10$ and Cobalt Strike JA3 match.
3. **DGA / DNS Tunnelling**: Click `[+ Algorithmic DGA Queries]` and `[+ DNS Exfiltration Chunk]`.
   - Alerts `DGA_DOMAIN` and `DNS_TUNNELLING` fire based on Shannon entropy $> 3.8$ bits without DNS lookup.
4. **Port Scanning / Host Discovery**: Click `[+ Vertical Port Sweep]`.
   - Alert `PORT_SCAN` fires with fan-out port sweeps.
5. **Data Exfiltration**: Click `[+ Data Exfiltration Burst]`.
   - Alert `POTENTIAL_DATA_EXFILTRATION` fires showing high outbound/inbound byte asymmetry.

---

## Step 4: Open Detailed Evidence Analysis Modal (6:00 - 7:30)
1. In the **Live Threat Alert Stream** table, click **Inspect** on any alert.
2. Point out:
   - **Confidence Score** (0.00 – 1.00) with calibrated multi-signal corroboration.
   - **Evidence Breakdown Table**: Observed Value vs. Baseline vs. Threshold and percentage deviation.
   - **Technical Explanation** and Enclave Guarantee notice.

---

## Step 5: Execute Real Throughput Benchmark (7:30 - 9:00)
1. Switch to the **Throughput Benchmark** tab.
2. Select **10,000 flows** and click **Execute Real Throughput Benchmark**.
3. Point out real wall-clock performance:
   - Throughput: $> 10,000\text{ flows/sec}$.
   - Average Processing Latency: $< 0.15\text{ ms}$.
   - P95 and P99 latency percentiles.
   - Hardware utilization and zero egress socket verification.

---

## Step 6: Review Deep Metadata Inspector & Airgap Audit (9:00 - 10:00)
1. Switch to **Deep Forensic Inspector** to show captured DNS strings and TLS JA3 fingerprints.
2. Switch to **Airgap Security Audit** to highlight static and runtime invariant proofs.
3. Conclude by confirming that the entire pipeline executed in a 100% read-only, zero return-path configuration.
