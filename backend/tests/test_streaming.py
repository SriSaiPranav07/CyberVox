"""
End-to-End Integration Tests for Passive Streaming Pipeline.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.pipeline import pipeline
from app.simulator.traffic_generator import SyntheticTrafficGenerator
from app.storage.alert_store import alert_store

class TestStreamingPipeline(unittest.TestCase):

    def setUp(self):
        pipeline.reset()
        alert_store.clear()

    def test_end_to_end_streaming_detection(self):
        # 1. Stream 50 benign flows
        for _ in range(50):
            flow = SyntheticTrafficGenerator.generate_benign_flow()
            pipeline.process_raw_flow(flow)

        metrics = pipeline.get_current_metrics()
        self.assertEqual(metrics.total_processed_flows, 50)

        # 2. Inject Port Scan threat burst
        scan_burst = SyntheticTrafficGenerator.generate_port_scan_burst(num_ports=25)
        for f in scan_burst:
            pipeline.process_raw_flow(f)

        # 3. Verify alert generation & metrics
        alerts = alert_store.get_alerts()
        self.assertGreaterEqual(len(alerts), 1)
        self.assertIn("PORT_SCAN", [a.threat_class for a in alerts])

        # 4. Latency verification
        metrics_after = pipeline.get_current_metrics()
        self.assertGreater(metrics_after.avg_processing_latency_ms, 0.0)
        self.assertLess(metrics_after.avg_processing_latency_ms, 50.0) # Sub-50ms latency

if __name__ == "__main__":
    unittest.main()
