"""
Hybrid Threat Detection Engine for SIH 2026.
Unifies Rule-based logic, Statistical Anomaly detection, and Machine Learning models (Random Forest + Isolation Forest)
to produce standardized, scored alerts with multi-dimensional evidence.
"""

from typing import List, Optional
from datetime import datetime
from app.detection.base import BaseThreatDetector
from app.detection.ddos_detector import DdosDetector
from app.detection.c2_detector import C2BeaconDetector
from app.detection.dns_detector import DnsThreatDetector
from app.detection.encrypted_detector import EncryptedTrafficDetector
from app.detection.recon_detector import ReconnaissanceDetector
from app.detection.exfil_detector import DataExfiltrationDetector
from app.ml.model_manager import ml_manager
from app.models.schemas import RawFlowRecord, Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType

class HybridDetectionEngine:
    def __init__(self):
        self.detectors: List[BaseThreatDetector] = [
            DdosDetector(),
            C2BeaconDetector(),
            DnsThreatDetector(),
            EncryptedTrafficDetector(),
            ReconnaissanceDetector(),
            DataExfiltrationDetector()
        ]

    def process_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        """
        Runs comprehensive threat analysis across domain detectors and ML models.
        """
        # 1. Run specialized domain detection modules
        for detector in self.detectors:
            alert = detector.analyze_flow(flow, context_window)
            if alert is not None:
                # Optionally corroborate with ML model
                ml_pred = ml_manager.predict_threat_class(flow)
                if ml_pred:
                    pred_class, ml_conf, _ = ml_pred
                    # Boost confidence slightly if ML model agrees
                    if pred_class.lower() in alert.threat_class.lower():
                        alert.confidence = min(0.99, round(alert.confidence * 0.7 + ml_conf * 0.3, 2))
                        alert.detection_engine = DetectionEngineType.HYBRID_ENSEMBLE
                return alert

        # 2. If domain detectors didn't trigger, check ML & Isolation Forest anomaly
        is_anom, anom_score, explanation = ml_manager.predict_anomaly(flow)
        ml_threat = ml_manager.predict_threat_class(flow)

        if ml_threat:
            threat_cls, conf, cat = ml_threat
            severity = SeverityLevel.HIGH if conf > 0.85 else SeverityLevel.MEDIUM
            
            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=cat,
                threat_class=threat_cls,
                severity=severity,
                confidence=conf,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                evidence={
                    "ml_confidence": conf,
                    "anomaly_score": anom_score,
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count,
                    "duration_sec": flow.duration_sec
                },
                evidence_details=[
                    EvidenceDetail(
                        feature_name="ml_classification_confidence",
                        observed_value=conf,
                        baseline_value=0.50,
                        threshold_value=0.60,
                        unit="probability",
                        interpretation=f"Supervised Random Forest classifier identified pattern signature with {round(conf*100, 1)}% confidence."
                    )
                ],
                explanation=f"Machine learning classifier identified {threat_cls} behavior based on network flow vector features.",
                detection_engine=DetectionEngineType.RANDOM_FOREST
            )

        if is_anom and anom_score > 0.80:
            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.RECON,
                threat_class=ThreatClass.RECONNAISSANCE.value,
                severity=SeverityLevel.LOW,
                confidence=round(anom_score, 2),
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                evidence={
                    "anomaly_score": anom_score,
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count
                },
                evidence_details=[
                    EvidenceDetail(
                        feature_name="isolation_forest_anomaly_score",
                        observed_value=anom_score,
                        baseline_value=0.30,
                        threshold_value=0.65,
                        unit="score",
                        interpretation="Statistical outlier detected in multi-dimensional feature space departure from benign baseline."
                    )
                ],
                explanation=f"Unsupervised network anomaly detected: {explanation}.",
                detection_engine=DetectionEngineType.ISOLATION_FOREST
            )

        return None

hybrid_engine = HybridDetectionEngine()
