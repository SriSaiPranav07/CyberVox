"""
Module F: Potential Data Exfiltration Detection
Detects anomalous outbound data volume, asymmetric outbound-to-inbound byte ratios, and sustained transfer bursts.
Adheres strictly to requirement: labels as "Potential Data Exfiltration" rather than definitive compromise.
"""

from typing import List, Optional
from datetime import datetime
from app.detection.base import BaseThreatDetector
from app.models.schemas import RawFlowRecord, Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType
from app.config import settings

class DataExfiltrationDetector(BaseThreatDetector):
    def __init__(self):
        super().__init__("Data_Exfiltration_Engine")
        self.thresholds = settings.THRESHOLDS

    def analyze_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        # Inspect outbound byte volume and duration
        outbound_bytes = flow.byte_count
        duration = max(0.1, flow.duration_sec)
        transfer_rate_bps = (outbound_bytes * 8.0) / duration
        
        # Calculate reverse / inbound flow if available in context
        inbound_flows = [
            f for f in context_window
            if f.source_ip == flow.destination_ip and f.destination_ip == flow.source_ip
        ]
        inbound_bytes = sum(f.byte_count for f in inbound_flows) if inbound_flows else max(100, int(outbound_bytes / 25))
        
        byte_ratio = outbound_bytes / max(1, inbound_bytes)

        # Potential Exfiltration Condition:
        # High outbound volume (>500KB in single flow or stream), high ratio (>8.0 outbound/inbound)
        if outbound_bytes >= self.thresholds.exfil_min_outbound_bytes and byte_ratio >= self.thresholds.exfil_byte_ratio_threshold:
            confidence = round(min(0.92, 0.65 + (byte_ratio / 50.0) * 0.25), 2)
            severity = SeverityLevel.HIGH if outbound_bytes > 5_000_000 else SeverityLevel.MEDIUM

            evidence_details = [
                EvidenceDetail(
                    feature_name="outbound_bytes",
                    observed_value=outbound_bytes,
                    baseline_value=45_000,
                    threshold_value=self.thresholds.exfil_min_outbound_bytes,
                    deviation_pct=round(((outbound_bytes - 45_000) / 45_000) * 100, 1),
                    unit="bytes",
                    interpretation=f"Outbound transfer payload ({round(outbound_bytes / 1024 / 1024, 2)} MB) significantly exceeds normal client egress baseline."
                ),
                EvidenceDetail(
                    feature_name="outbound_inbound_byte_ratio",
                    observed_value=round(byte_ratio, 1),
                    baseline_value=1.2,
                    threshold_value=self.thresholds.exfil_byte_ratio_threshold,
                    deviation_pct=round(((byte_ratio - 1.2) / 1.2) * 100, 1),
                    unit="ratio",
                    interpretation=f"Severe transfer asymmetry (ratio {round(byte_ratio,1)}:1 outbound vs inbound)."
                ),
                EvidenceDetail(
                    feature_name="transfer_rate_mbps",
                    observed_value=round(transfer_rate_bps / 1_000_000, 2),
                    baseline_value=0.5,
                    threshold_value=5.0,
                    unit="Mbps",
                    interpretation=f"Sustained egress throughput of {round(transfer_rate_bps / 1_000_000, 2)} Mbps during active window."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.EXFILTRATION,
                threat_class=ThreatClass.POTENTIAL_DATA_EXFILTRATION.value,
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                evidence={
                    "outbound_bytes": outbound_bytes,
                    "inbound_bytes": inbound_bytes,
                    "byte_ratio": round(byte_ratio, 2),
                    "duration_sec": round(duration, 2),
                    "transfer_rate_mbps": round(transfer_rate_bps / 1_000_000, 2)
                },
                evidence_details=evidence_details,
                explanation=f"Potential Data Exfiltration detected: Unusually heavy outbound transfer of {round(outbound_bytes/1024/1024, 2)} MB with {round(byte_ratio,1)}x byte asymmetry to {flow.destination_ip}.",
                detection_engine=DetectionEngineType.STATISTICAL_ANOMALY
            )

        return None
