"""
Module C: DGA Domains & DNS Tunnelling Detection
Analyzes DNS metadata strictly without resolving or contacting suspicious domains.
"""

from typing import List, Optional
from datetime import datetime
from app.detection.base import BaseThreatDetector
from app.models.schemas import RawFlowRecord, Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType
from app.config import settings
from app.core.feature_extractor import calculate_dns_features

class DnsThreatDetector(BaseThreatDetector):
    def __init__(self):
        super().__init__("DNS_Threat_Engine")
        self.thresholds = settings.THRESHOLDS

    def analyze_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        # Analyze flow if DNS query metadata exists or if protocol/port is DNS (port 53)
        query = flow.dns_query
        if not query:
            return None

        dns_feats = calculate_dns_features(query)
        entropy = dns_feats["shannon_entropy"]
        length = dns_feats["domain_length"]
        main_len = dns_feats["main_label_length"]
        digit_ratio = dns_feats["digit_ratio"]
        consecutive_consonants = dns_feats["consecutive_consonants_max"]
        has_hex = dns_feats["has_hex_pattern"]
        subdomain_count = dns_feats["subdomain_count"]

        # 1. DNS Tunnelling (High entropy, high length, hex/base32 payload chunks, TXT/NULL queries)
        is_tunnel = (has_hex and main_len >= 16) or (length >= 35 and entropy >= 3.8) or (flow.dns_record_type in ["TXT", "NULL"] and length >= 30)

        if is_tunnel:
            confidence = round(min(0.98, 0.78 + (entropy / 5.0) * 0.20), 2)
            severity = SeverityLevel.HIGH

            evidence_details = [
                EvidenceDetail(
                    feature_name="domain_length",
                    observed_value=length,
                    baseline_value=12,
                    threshold_value=self.thresholds.dga_length_threshold,
                    deviation_pct=round(((length - 12) / 12) * 100, 1),
                    unit="chars",
                    interpretation=f"Extensive query label length ({length} characters) typical of data encapsulation."
                ),
                EvidenceDetail(
                    feature_name="shannon_entropy",
                    observed_value=entropy,
                    baseline_value=2.40,
                    threshold_value=self.thresholds.dga_entropy_threshold,
                    deviation_pct=round(((entropy - 2.40) / 2.40) * 100, 1),
                    unit="bits",
                    interpretation=f"High Shannon entropy ({entropy} bits) indicates encrypted or base-encoded payload in DNS label."
                ),
                EvidenceDetail(
                    feature_name="subdomain_depth",
                    observed_value=subdomain_count,
                    baseline_value=2,
                    threshold_value=self.thresholds.dns_subdomain_depth_max,
                    unit="levels",
                    interpretation=f"Deep subdomain nesting ({subdomain_count} levels) used for data transport chunks."
                ),
                EvidenceDetail(
                    feature_name="hex_encoding_pattern",
                    observed_value=str(has_hex),
                    baseline_value="False",
                    threshold_value="True",
                    unit="boolean",
                    interpretation="Payload contains high-density hex/encoded chunk characters."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.DNS,
                threat_class=ThreatClass.DNS_TUNNELLING.value,
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol="DNS",
                evidence={
                    "query": query,
                    "domain_length": length,
                    "shannon_entropy": entropy,
                    "record_type": flow.dns_record_type or "A",
                    "subdomain_count": subdomain_count,
                    "has_hex_pattern": has_hex
                },
                evidence_details=evidence_details,
                explanation=f"DNS covert data exfiltration / tunnelling detected via query metadata '{query}' without active DNS lookup.",
                detection_engine=DetectionEngineType.HYBRID_ENSEMBLE
            )

        # 2. DGA Domain Detection (Domain Generation Algorithm)
        is_dga = (entropy >= self.thresholds.dga_entropy_threshold and length >= 14) or (consecutive_consonants >= 5 and entropy >= 3.4) or (digit_ratio >= 0.35 and length >= 12)

        if is_dga:
            confidence = round(min(0.95, 0.72 + (entropy / 4.5) * 0.22), 2)
            severity = SeverityLevel.MEDIUM

            evidence_details = [
                EvidenceDetail(
                    feature_name="shannon_entropy",
                    observed_value=entropy,
                    baseline_value=2.40,
                    threshold_value=self.thresholds.dga_entropy_threshold,
                    deviation_pct=round(((entropy - 2.40) / 2.40) * 100, 1),
                    unit="bits",
                    interpretation=f"Randomness score of {entropy} bits strongly departs from natural human language distributions."
                ),
                EvidenceDetail(
                    feature_name="consecutive_consonants",
                    observed_value=consecutive_consonants,
                    baseline_value=2,
                    threshold_value=4,
                    unit="chars",
                    interpretation=f"Abnormal consonant cluster length ({consecutive_consonants}) confirms pseudo-random character generation."
                ),
                EvidenceDetail(
                    feature_name="digit_ratio",
                    observed_value=digit_ratio,
                    baseline_value=0.05,
                    threshold_value=0.25,
                    unit="ratio",
                    interpretation=f"Digit-to-letter ratio of {digit_ratio} aligns with algorithmic domain generation."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.DNS,
                threat_class=ThreatClass.DGA_DOMAIN.value,
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol="DNS",
                evidence={
                    "query": query,
                    "shannon_entropy": entropy,
                    "domain_length": length,
                    "digit_ratio": digit_ratio,
                    "consecutive_consonants_max": consecutive_consonants
                },
                evidence_details=evidence_details,
                explanation=f"Algorithmic pseudo-random domain (DGA) pattern recognized in metadata query '{query}' (No external query issued).",
                detection_engine=DetectionEngineType.STATISTICAL_ANOMALY
            )

        return None
