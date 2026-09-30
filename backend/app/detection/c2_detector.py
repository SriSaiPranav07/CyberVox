"""
Module B: Botnet C2 Beaconing Detection
Identifies repeated periodic communication patterns and time-series regularity without contacting the destination.
"""

from typing import List, Optional
from datetime import datetime
from app.detection.base import BaseThreatDetector
from app.models.schemas import RawFlowRecord, Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType
from app.config import settings
from app.core.feature_extractor import calculate_time_series_periodicity

class C2BeaconDetector(BaseThreatDetector):
    def __init__(self):
        super().__init__("C2_Beacon_Engine")
        self.thresholds = settings.THRESHOLDS

    def analyze_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        recent = context_window[-80:]
        # Filter window for communication between this specific source and destination pair
        pair_flows = [
            f for f in recent 
            if f.source_ip == flow.source_ip and f.destination_ip == flow.destination_ip and f.destination_port == flow.destination_port
        ]

        if len(pair_flows) < self.thresholds.c2_min_occurrences:
            return None

        timestamps = [f.timestamp for f in pair_flows]
        period_metrics = calculate_time_series_periodicity(timestamps)

        is_periodic = period_metrics["is_periodic"]
        cv = period_metrics["jitter_cv"]
        mean_iat = period_metrics["mean_iat_sec"]
        periodicity_score = period_metrics["periodicity_score"]
        samples = period_metrics["sample_count"]

        # If strict periodicity is observed with low jitter coefficient
        if is_periodic or (cv <= self.thresholds.c2_iat_jitter_max and samples >= 5):
            confidence = round(min(0.96, 0.70 + (periodicity_score * 0.26)), 2)
            severity = SeverityLevel.HIGH if samples >= 8 else SeverityLevel.MEDIUM

            evidence_details = [
                EvidenceDetail(
                    feature_name="mean_inter_arrival_time",
                    observed_value=mean_iat,
                    baseline_value="Random / Poisson",
                    threshold_value=f"Regular interval ~ {mean_iat}s",
                    unit="seconds",
                    interpretation=f"Mean beacon cadence is consistently spaced every {mean_iat} seconds."
                ),
                EvidenceDetail(
                    feature_name="jitter_cv",
                    observed_value=cv,
                    baseline_value=0.75,
                    threshold_value=self.thresholds.c2_iat_jitter_max,
                    deviation_pct=round(((0.75 - cv) / 0.75) * 100, 1),
                    unit="ratio",
                    interpretation=f"Extremely low inter-arrival jitter (CV = {cv}) indicates automated programmatic beaconing rather than human activity."
                ),
                EvidenceDetail(
                    feature_name="periodicity_score",
                    observed_value=periodicity_score,
                    baseline_value=0.10,
                    threshold_value=self.thresholds.c2_periodicity_confidence_min,
                    unit="score",
                    interpretation=f"Time-series autocorrelation regularity score of {periodicity_score} demonstrates robotic periodicity."
                ),
                EvidenceDetail(
                    feature_name="repeated_contact_count",
                    observed_value=samples,
                    baseline_value=1,
                    threshold_value=self.thresholds.c2_min_occurrences,
                    unit="beacons",
                    interpretation=f"Detected {samples} recurring communication bursts to destination {flow.destination_ip}:{flow.destination_port}."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.C2,
                threat_class=ThreatClass.C2_BEACONING.value,
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                evidence={
                    "mean_iat_sec": mean_iat,
                    "jitter_cv": cv,
                    "periodicity_score": periodicity_score,
                    "beacon_count": samples,
                    "destination_port": flow.destination_port
                },
                evidence_details=evidence_details,
                explanation=f"Botnet Command & Control (C2) heartbeat beaconing pattern detected with ~{mean_iat}s interval and robotic CV of {cv}.",
                detection_engine=DetectionEngineType.STATISTICAL_ANOMALY
            )

        return None
