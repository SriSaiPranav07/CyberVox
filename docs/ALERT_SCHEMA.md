# Standardized Alert Schema (Section 12 Compliance)

Every detection in the enclave produces a standardized structured JSON alert.

## Alert Specification

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
      "interpretation": "SYN packet arrival rate (18420.0 pkts/s) exceeds threshold (1200.0 pkts/s)."
    }
  ],
  "explanation": "Abnormally high SYN rate and source diversity targeting a concentrated destination in passive monitoring window.",
  "detection_engine": "HYBRID_ENSEMBLE",
  "processing_latency_ms": 0.342
}
```

## Field Semantics
- **`confidence`**: $[0.00, 1.00]$ — Represents strength and multi-signal corroboration of supporting technical evidence.
- **`severity`**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` — Represents potential operational impact.
- **`evidence`**: Machine-readable feature dictionary.
- **`evidence_details`**: Human-readable breakdown showing observed values, baseline values, threshold values, and percentage deviation.
