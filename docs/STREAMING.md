# Streaming Architecture & Window Management

## Incremental Processing Pipeline

The system processes continuous traffic incrementally rather than performing end-of-run batch analysis.

```
Traffic Stream (Replay / Passive Ingest)
           |
           v
  Streaming Ingest & Validation
           |
           v
  Sliding Window Accumulator (1s, 5s, 30s, 60s)
           |
           v
  Incremental Feature Processor
           |
           v
  Hybrid Threat Scorer
           |
           v
  Alert Bus & In-Memory Storage
           |
           v
  WebSocket Broadcast (/ws/stream)
           |
           v
  SOC Cyber Defense Dashboard
```

## Window Semantics
- **1-Second Window**: Immediate volumetric rate spikes (SYN floods, UDP storms).
- **5-Second Window**: Rapid fan-out scans and short-burst exfiltration.
- **30-Second Window**: Moderate cadence Botnet C2 beaconing heartbeats.
- **60-Second Window**: Long-term slow beaconing, low-frequency horizontal sweeps, and sustained egress baseline deviation.
