"""
Module A: Volumetric & Protocol DDoS Detection
Detects SYN Floods, UDP Floods, UDP Reflection/Amplification, and Spoofed-Source Floods.
"""

from typing import List, Optional
from datetime import datetime
from app.detection.base import BaseThreatDetector
from app.models.schemas import RawFlowRecord, Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType
from app.config import settings
from app.core.feature_extractor import calculate_window_features

class DdosDetector(BaseThreatDetector):
    def __init__(self):
        super().__init__("DDoS_Detection_Engine")
        self.thresholds = settings.THRESHOLDS

    def analyze_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        if not context_window or len(context_window) < 5:
            return None

        recent = context_window[-80:]
        target_dst = flow.destination_ip
        dst_window = [f for f in recent if f.destination_ip == target_dst]
        if len(dst_window) < 5:
            return None

        features = calculate_window_features(dst_window)
        total_packets = features.get("total_packets", 0)
        syn_count = features.get("syn_count", 0)
        udp_count = features.get("udp_count", 0)
        unique_sources = features.get("unique_sources", 1)
        source_entropy = features.get("source_entropy", 0.0)
        dst_concentration = features.get("destination_concentration", 0.0)
        
        # Duration estimation of the context window (min 1 sec)
        time_span = max(1.0, max(f.timestamp for f in dst_window) - min(f.timestamp for f in dst_window))
        syn_rate = syn_count / time_span
        udp_rate = udp_count / time_span
        pkt_rate = total_packets / time_span

        # 1. SYN Flood Detection
        if syn_rate >= self.thresholds.syn_flood_rate_threshold or (syn_count >= 50 and unique_sources >= 10):
            # Evidence strength calculation (Confidence 0.00 - 1.00)
            confidence = min(0.99, 0.70 + (syn_rate / (self.thresholds.syn_flood_rate_threshold * 2.0)) * 0.29)
            confidence = round(confidence, 2)
            
            severity = SeverityLevel.CRITICAL if syn_rate > 2000 else SeverityLevel.HIGH
            
            evidence_details = [
                EvidenceDetail(
                    feature_name="syn_rate",
                    observed_value=round(syn_rate, 1),
                    baseline_value=150.0,
                    threshold_value=self.thresholds.syn_flood_rate_threshold,
                    deviation_pct=round(((syn_rate - 150.0) / 150.0) * 100, 1),
                    unit="pkts/sec",
                    interpretation=f"SYN packet arrival rate ({round(syn_rate,1)} pkts/s) exceeds threshold ({self.thresholds.syn_flood_rate_threshold} pkts/s)."
                ),
                EvidenceDetail(
                    feature_name="unique_sources",
                    observed_value=unique_sources,
                    baseline_value=5,
                    threshold_value=10,
                    deviation_pct=round(((unique_sources - 5) / 5) * 100, 1),
                    unit="hosts",
                    interpretation=f"Distributed source diversity with {unique_sources} distinct origin IPs."
                ),
                EvidenceDetail(
                    feature_name="source_entropy",
                    observed_value=source_entropy,
                    baseline_value=0.35,
                    threshold_value=self.thresholds.source_entropy_flood_min,
                    deviation_pct=round(((source_entropy - 0.35) / 0.35) * 100, 1),
                    unit="bits",
                    interpretation=f"High source IP Shannon entropy ({source_entropy} bits) indicates distributed or spoofed origin."
                ),
                EvidenceDetail(
                    feature_name="destination_concentration",
                    observed_value=dst_concentration,
                    baseline_value=0.20,
                    threshold_value=self.thresholds.destination_concentration_min,
                    deviation_pct=round(((dst_concentration - 0.20) / 0.20) * 100, 1),
                    unit="ratio",
                    interpretation=f"Target concentration index ({dst_concentration}) confirms asymmetric focus on {target_dst}."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.DDOS,
                threat_class=ThreatClass.DDOS_SYN_FLOOD.value,
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=target_dst,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol="TCP",
                evidence={
                    "syn_rate": round(syn_rate, 1),
                    "unique_sources": unique_sources,
                    "source_entropy": source_entropy,
                    "destination_concentration": dst_concentration,
                    "packets_per_sec": round(pkt_rate, 1)
                },
                evidence_details=evidence_details,
                explanation="Abnormally high SYN rate and source diversity targeting a concentrated destination in passive monitoring window.",
                detection_engine=DetectionEngineType.HYBRID_ENSEMBLE
            )

        # 2. UDP Flood / Amplification Detection
        if udp_rate >= self.thresholds.udp_flood_rate_threshold or (udp_count >= 80 and pkt_rate >= 1500):
            confidence = min(0.98, 0.75 + (udp_rate / (self.thresholds.udp_flood_rate_threshold * 2.0)) * 0.23)
            confidence = round(confidence, 2)
            
            is_amp = (flow.source_port in [53, 123, 1900, 389, 11211]) and (flow.byte_count / max(1, flow.packet_count) > 800)
            threat_cls = ThreatClass.DDOS_AMPLIFICATION.value if is_amp else ThreatClass.DDOS_UDP_FLOOD.value
            severity = SeverityLevel.CRITICAL

            evidence_details = [
                EvidenceDetail(
                    feature_name="udp_rate",
                    observed_value=round(udp_rate, 1),
                    baseline_value=200.0,
                    threshold_value=self.thresholds.udp_flood_rate_threshold,
                    deviation_pct=round(((udp_rate - 200.0) / 200.0) * 100, 1),
                    unit="pkts/sec",
                    interpretation=f"UDP packet volumetric rate ({round(udp_rate,1)} pkts/s) overwhelming receiver bandwidth."
                ),
                EvidenceDetail(
                    feature_name="destination_concentration",
                    observed_value=dst_concentration,
                    baseline_value=0.20,
                    threshold_value=self.thresholds.destination_concentration_min,
                    deviation_pct=round(((dst_concentration - 0.20) / 0.20) * 100, 1),
                    unit="ratio",
                    interpretation=f"Heavy volumetric influx focused at {target_dst}:{flow.destination_port}."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.DDOS,
                threat_class=threat_cls,
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=target_dst,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol="UDP",
                evidence={
                    "udp_rate": round(udp_rate, 1),
                    "unique_sources": unique_sources,
                    "packets_per_sec": round(pkt_rate, 1),
                    "destination_concentration": dst_concentration
                },
                evidence_details=evidence_details,
                explanation=f"Volumetric {'amplification reflection' if is_amp else 'UDP packet flood'} detected without active intervention.",
                detection_engine=DetectionEngineType.HYBRID_ENSEMBLE
            )

        return None
