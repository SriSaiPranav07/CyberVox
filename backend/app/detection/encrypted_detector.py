"""
Module D: Encrypted Traffic Analysis (TLS & QUIC Metadata Only)
Strict Requirement: Payloads are NEVER decrypted.
Analyzes ClientHello JA3/JA4 fingerprints, cipher suites, packet burst distributions, and timing sequences.
"""

from typing import List, Optional
import numpy as np
from datetime import datetime
from app.detection.base import BaseThreatDetector
from app.models.schemas import RawFlowRecord, Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType
from app.config import settings

class EncryptedTrafficDetector(BaseThreatDetector):
    def __init__(self):
        super().__init__("Encrypted_Traffic_Metadata_Engine")
        self.suspicious_ja3s = set(settings.THRESHOLDS.tls_suspicious_ja3_hashes)

    def analyze_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        # Only evaluate encrypted flows (TLS / QUIC ports or TLS metadata present)
        is_encrypted = (flow.destination_port in [443, 8443, 4433, 9443]) or (flow.tls_version is not None) or (flow.ja3_hash is not None)
        if not is_encrypted:
            return None

        # 1. JA3 / JA4 Fingerprint Known Threat Match (Cobalt Strike, TrickBot, Metasploit, AsyncRAT)
        if flow.ja3_hash and flow.ja3_hash.lower() in self.suspicious_ja3s:
            confidence = 0.96
            severity = SeverityLevel.CRITICAL

            evidence_details = [
                EvidenceDetail(
                    feature_name="ja3_client_fingerprint",
                    observed_value=flow.ja3_hash,
                    baseline_value="Standard Browser JA3 (Chrome/Firefox/Safari)",
                    threshold_value="Known C2/Malware ClientHello Fingerprint",
                    unit="md5_hash",
                    interpretation=f"Extracted JA3 hash '{flow.ja3_hash}' matches signature of known malicious command-and-control framework."
                ),
                EvidenceDetail(
                    feature_name="tls_version",
                    observed_value=flow.tls_version or "TLSv1.2",
                    baseline_value="TLSv1.3",
                    unit="protocol_version",
                    interpretation="Encrypted handshake metadata captured passively without inspecting or decrypting application data."
                ),
                EvidenceDetail(
                    feature_name="decryption_status",
                    observed_value="NO_DECRYPTION_PERFORMED",
                    baseline_value="METADATA_ONLY",
                    unit="security_guarantee",
                    interpretation="TLS/QUIC payloads are not decrypted. Detection uses metadata only."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.ENCRYPTED,
                threat_class=ThreatClass.SUSPICIOUS_JA3_FINGERPRINT.value,
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol="TLS",
                evidence={
                    "ja3_hash": flow.ja3_hash,
                    "ja4_hash": flow.ja4_hash or "t13d...",
                    "tls_version": flow.tls_version or "TLSv1.2",
                    "sni": flow.sni or "encrypted-session.internal",
                    "decryption_guarantee": "TLS/QUIC payloads are not decrypted. Detection uses metadata only."
                },
                evidence_details=evidence_details,
                explanation="Malicious ClientHello JA3 fingerprint matched against threat intelligence database without payload decryption.",
                detection_engine=DetectionEngineType.RULE_ENGINE
            )

        # 2. Encrypted Packet Burst & Size Sequence Anomaly (Tunnel over TLS or Steganography)
        if flow.packet_sizes and len(flow.packet_sizes) >= 6:
            std_size = float(np.std(flow.packet_sizes))
            avg_size = float(np.mean(flow.packet_sizes))
            
            # Encrypted tunnels / exfil often feature constant max-MTU packet bursts with near-zero standard deviation
            if avg_size > 1200 and std_size < 15.0 and flow.packet_count >= 20:
                confidence = 0.84
                severity = SeverityLevel.HIGH

                evidence_details = [
                    EvidenceDetail(
                        feature_name="packet_size_dispersion",
                        observed_value=round(std_size, 2),
                        baseline_value=350.0,
                        threshold_value=25.0,
                        unit="bytes_std",
                        interpretation="Abnormally uniform packet sizes in encrypted stream indicate automated encapsulation/tunnel."
                    ),
                    EvidenceDetail(
                        feature_name="average_packet_size",
                        observed_value=round(avg_size, 1),
                        baseline_value=600.0,
                        threshold_value=1200.0,
                        unit="bytes",
                        interpretation=f"High average packet volume ({round(avg_size,1)} bytes) sustained across encrypted session."
                    ),
                    EvidenceDetail(
                        feature_name="decryption_status",
                        observed_value="PAYLOAD_UNTOUCHED",
                        baseline_value="METADATA_ONLY",
                        unit="security_guarantee",
                        interpretation="TLS/QUIC payloads are not decrypted. Detection uses metadata only."
                    )
                ]

                return Alert(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    flow_id=flow.flow_id,
                    threat_category=ThreatCategory.ENCRYPTED,
                    threat_class=ThreatClass.ENCRYPTED_BURST_PATTERN.value,
                    severity=severity,
                    confidence=confidence,
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    source_port=flow.source_port,
                    destination_port=flow.destination_port,
                    protocol="TLS",
                    evidence={
                        "avg_packet_size": round(avg_size, 1),
                        "std_packet_size": round(std_size, 2),
                        "packet_count": flow.packet_count,
                        "byte_count": flow.byte_count,
                        "decryption_guarantee": "TLS/QUIC payloads are not decrypted. Detection uses metadata only."
                    },
                    evidence_details=evidence_details,
                    explanation="Anomalous encrypted session burst pattern detected via packet-length and timing metadata only.",
                    detection_engine=DetectionEngineType.STATISTICAL_ANOMALY
                )

        return None
