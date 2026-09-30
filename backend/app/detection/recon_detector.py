"""
Module E: Reconnaissance & Port Scanning Detection
Detects Horizontal Scanning (host discovery), Vertical Scanning (port sweeping), and high fan-out probes.
"""

from typing import List, Optional
from datetime import datetime
from app.detection.base import BaseThreatDetector
from app.models.schemas import RawFlowRecord, Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType
from app.config import settings

class ReconnaissanceDetector(BaseThreatDetector):
    def __init__(self):
        super().__init__("Reconnaissance_Scan_Engine")
        self.thresholds = settings.THRESHOLDS

    def analyze_flow(self, flow: RawFlowRecord, context_window: List[RawFlowRecord]) -> Optional[Alert]:
        recent = context_window[-80:]
        src_ip = flow.source_ip
        src_flows = [f for f in recent if f.source_ip == src_ip]

        if len(src_flows) < 6:
            return None

        dest_ips = set(f.destination_ip for f in src_flows)
        dest_ports = set(f.destination_port for f in src_flows)
        
        # Calculate time span
        time_span = max(0.5, max(f.timestamp for f in src_flows) - min(f.timestamp for f in src_flows))
        scan_rate = len(src_flows) / time_span

        unique_hosts = len(dest_ips)
        unique_ports = len(dest_ports)

        # 1. Vertical Port Scan (One source IP hitting many ports on a single or few target IPs)
        if unique_ports >= self.thresholds.recon_unique_ports_threshold and unique_hosts <= 3:
            confidence = round(min(0.97, 0.75 + (unique_ports / 50.0) * 0.22), 2)
            severity = SeverityLevel.HIGH if unique_ports > 30 else SeverityLevel.MEDIUM

            evidence_details = [
                EvidenceDetail(
                    feature_name="unique_ports_scanned",
                    observed_value=unique_ports,
                    baseline_value=2,
                    threshold_value=self.thresholds.recon_unique_ports_threshold,
                    deviation_pct=round(((unique_ports - 2) / 2) * 100, 1),
                    unit="ports",
                    interpretation=f"Source swept {unique_ports} distinct target ports on host {flow.destination_ip}."
                ),
                EvidenceDetail(
                    feature_name="scan_rate",
                    observed_value=round(scan_rate, 1),
                    baseline_value=1.5,
                    threshold_value=self.thresholds.recon_scan_rate_threshold,
                    unit="probes/sec",
                    interpretation=f"Probe velocity of {round(scan_rate,1)} attempts/s exceeds normal application behavior."
                ),
                EvidenceDetail(
                    feature_name="fan_out_type",
                    observed_value="VERTICAL_PORT_SWEEP",
                    baseline_value="NORMAL_CLIENT",
                    unit="classification",
                    interpretation="Targeted service discovery pattern mapping exposed listening daemons."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.RECON,
                threat_class=ThreatClass.PORT_SCAN.value,
                severity=severity,
                confidence=confidence,
                source_ip=src_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                evidence={
                    "unique_ports": unique_ports,
                    "target_hosts": unique_hosts,
                    "scan_rate_fps": round(scan_rate, 1),
                    "total_attempts": len(src_flows)
                },
                evidence_details=evidence_details,
                explanation=f"Vertical port sweep reconnaissance detected: Source {src_ip} probed {unique_ports} ports on target {flow.destination_ip}.",
                detection_engine=DetectionEngineType.STATISTICAL_ANOMALY
            )

        # 2. Horizontal Host Discovery Scan (One source IP hitting the same port across many different target IPs)
        if unique_hosts >= self.thresholds.recon_unique_hosts_threshold:
            confidence = round(min(0.96, 0.73 + (unique_hosts / 50.0) * 0.23), 2)
            severity = SeverityLevel.HIGH

            evidence_details = [
                EvidenceDetail(
                    feature_name="unique_hosts_probed",
                    observed_value=unique_hosts,
                    baseline_value=3,
                    threshold_value=self.thresholds.recon_unique_hosts_threshold,
                    deviation_pct=round(((unique_hosts - 3) / 3) * 100, 1),
                    unit="hosts",
                    interpretation=f"Source initiated connection attempts against {unique_hosts} distinct subnet IP addresses."
                ),
                EvidenceDetail(
                    feature_name="probed_port",
                    observed_value=flow.destination_port,
                    baseline_value="Varied",
                    threshold_value=str(flow.destination_port),
                    unit="port",
                    interpretation=f"Consistent horizontal probing focused on port {flow.destination_port} ({flow.protocol})."
                ),
                EvidenceDetail(
                    feature_name="scan_rate",
                    observed_value=round(scan_rate, 1),
                    baseline_value=2.0,
                    threshold_value=self.thresholds.recon_scan_rate_threshold,
                    unit="probes/sec",
                    interpretation=f"Rapid network sweep velocity ({round(scan_rate,1)} probes/s)."
                )
            ]

            return Alert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                flow_id=flow.flow_id,
                threat_category=ThreatCategory.RECON,
                threat_class=ThreatClass.HOST_SCAN.value,
                severity=severity,
                confidence=confidence,
                source_ip=src_ip,
                destination_ip=flow.destination_ip,
                source_port=flow.source_port,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                evidence={
                    "unique_hosts": unique_hosts,
                    "target_port": flow.destination_port,
                    "scan_rate_fps": round(scan_rate, 1),
                    "total_attempts": len(src_flows)
                },
                evidence_details=evidence_details,
                explanation=f"Horizontal host discovery sweep detected: Source {src_ip} scanned {unique_hosts} hosts across subnet on port {flow.destination_port}.",
                detection_engine=DetectionEngineType.STATISTICAL_ANOMALY
            )

        return None
