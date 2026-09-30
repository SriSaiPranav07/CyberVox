"""
Unit Tests for all 6 Threat Detection Categories.
"""

import sys
import os
import unittest
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.schemas import RawFlowRecord
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel
from app.detection.ddos_detector import DdosDetector
from app.detection.c2_detector import C2BeaconDetector
from app.detection.dns_detector import DnsThreatDetector
from app.detection.encrypted_detector import EncryptedTrafficDetector
from app.detection.recon_detector import ReconnaissanceDetector
from app.detection.exfil_detector import DataExfiltrationDetector
from app.simulator.traffic_generator import SyntheticTrafficGenerator
from app.core.ingest import ingest_validator

class TestThreatDetectors(unittest.TestCase):

    def test_ddos_syn_flood_detector(self):
        detector = DdosDetector()
        burst = SyntheticTrafficGenerator.generate_ddos_syn_burst(target_ip="10.0.1.15", count=70)
        flows = [ingest_validator.sanitize_flow_record(f) for f in burst]
        
        alert = None
        for f in flows:
            alert = detector.analyze_flow(f, flows)
            if alert:
                break

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_category, ThreatCategory.DDOS)
        self.assertIn("SYN", alert.threat_class)
        self.assertGreaterEqual(alert.confidence, 0.70)
        self.assertIn("syn_rate", alert.evidence)

    def test_c2_beacon_detector(self):
        detector = C2BeaconDetector()
        beacon_burst = SyntheticTrafficGenerator.generate_c2_beacon(src_ip="10.0.1.42", c2_ip="185.220.101.5", count=8, interval_sec=1.5)
        flows = [ingest_validator.sanitize_flow_record(f) for f in beacon_burst]

        alert = None
        for f in flows:
            alert = detector.analyze_flow(f, flows)
            if alert:
                break

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_category, ThreatCategory.C2)
        self.assertEqual(alert.threat_class, ThreatClass.C2_BEACONING.value)
        self.assertLess(alert.evidence["jitter_cv"], 0.20)

    def test_dga_and_dns_tunnel_detector(self):
        detector = DnsThreatDetector()
        
        # Test DGA
        dga_raw = SyntheticTrafficGenerator.generate_dga_flow(src_ip="10.0.2.10")
        dga_flow = ingest_validator.sanitize_flow_record(dga_raw)
        alert_dga = detector.analyze_flow(dga_flow, [dga_flow])
        self.assertIsNotNone(alert_dga)
        self.assertEqual(alert_dga.threat_category, ThreatCategory.DNS)
        self.assertIn("DGA", alert_dga.threat_class)

        # Test DNS Tunnel
        tunnel_raw = SyntheticTrafficGenerator.generate_dns_tunnel_flow(src_ip="10.0.2.55")
        tunnel_flow = ingest_validator.sanitize_flow_record(tunnel_raw)
        alert_tunnel = detector.analyze_flow(tunnel_flow, [tunnel_flow])
        self.assertIsNotNone(alert_tunnel)
        self.assertEqual(alert_tunnel.threat_class, ThreatClass.DNS_TUNNELLING.value)

    def test_encrypted_traffic_ja3_detector(self):
        detector = EncryptedTrafficDetector()
        flow_raw = {
            "flow_id": "tls-flow-1",
            "timestamp": time.time(),
            "source_ip": "10.0.1.42",
            "destination_ip": "185.220.101.5",
            "source_port": 49120,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 5,
            "byte_count": 600,
            "duration_sec": 0.1,
            "tls_version": "TLSv1.2",
            "ja3_hash": "6734f37431670b3ab4292b8f60f29984" # Cobalt Strike JA3
        }
        flow = ingest_validator.sanitize_flow_record(flow_raw)
        alert = detector.analyze_flow(flow, [flow])
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_category, ThreatCategory.ENCRYPTED)
        self.assertIn("decryption_guarantee", alert.evidence)

    def test_reconnaissance_detector(self):
        detector = ReconnaissanceDetector()
        burst = SyntheticTrafficGenerator.generate_port_scan_burst(src_ip="192.168.1.210", target_ip="10.0.1.88", num_ports=25)
        flows = [ingest_validator.sanitize_flow_record(f) for f in burst]

        alert = None
        for f in flows:
            alert = detector.analyze_flow(f, flows)
            if alert:
                break

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_category, ThreatCategory.RECON)
        self.assertEqual(alert.threat_class, ThreatClass.PORT_SCAN.value)

    def test_data_exfiltration_detector(self):
        detector = DataExfiltrationDetector()
        raw = SyntheticTrafficGenerator.generate_data_exfiltration_flow(src_ip="10.0.1.15", dst_ip="203.0.113.88")
        flow = ingest_validator.sanitize_flow_record(raw)

        alert = detector.analyze_flow(flow, [flow])
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_category, ThreatCategory.EXFILTRATION)
        self.assertEqual(alert.threat_class, ThreatClass.POTENTIAL_DATA_EXFILTRATION.value)
        self.assertIn("byte_ratio", alert.evidence)

if __name__ == "__main__":
    unittest.main()
