"""
Unit Tests for Standard Alert Schema, Confidence, and Severity Compliance.
"""

import sys
import os
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.schemas import Alert, EvidenceDetail
from app.models.threat_types import ThreatCategory, ThreatClass, SeverityLevel, DetectionEngineType

class TestAlertSchema(unittest.TestCase):

    def test_alert_fields_and_types(self):
        alert = Alert(
            timestamp=datetime.utcnow().isoformat() + "Z",
            flow_id="flow-18472",
            threat_category=ThreatCategory.DDOS,
            threat_class=ThreatClass.DDOS_SYN_FLOOD.value,
            severity=SeverityLevel.CRITICAL,
            confidence=0.97,
            source_ip="192.168.1.10",
            destination_ip="10.0.0.20",
            source_port=48210,
            destination_port=443,
            protocol="TCP",
            evidence={
                "syn_rate": 18420,
                "unique_sources": 8231,
                "source_entropy": 0.94,
                "destination_concentration": 0.91
            },
            evidence_details=[
                EvidenceDetail(
                    feature_name="syn_rate",
                    observed_value=18420,
                    baseline_value=2000,
                    deviation_pct=821.0,
                    interpretation="Abnormally high SYN rate"
                )
            ],
            explanation="Abnormally high SYN rate and source diversity targeting a concentrated destination.",
            detection_engine=DetectionEngineType.HYBRID_ENSEMBLE,
            processing_latency_ms=0.342
        )

        # Validate JSON serialization
        json_data = alert.model_dump()
        self.assertIn("timestamp", json_data)
        self.assertIn("flow_id", json_data)
        self.assertIn("threat_class", json_data)
        self.assertIn("confidence", json_data)
        self.assertIn("evidence", json_data)
        self.assertIn("explanation", json_data)
        
        self.assertGreaterEqual(alert.confidence, 0.0)
        self.assertLessEqual(alert.confidence, 1.0)
        self.assertEqual(alert.severity, SeverityLevel.CRITICAL)

if __name__ == "__main__":
    unittest.main()
