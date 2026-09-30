"""
Unit Tests for Feature Extraction, Entropy, and Periodicity.
"""

import math
import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.feature_extractor import (
    calculate_shannon_entropy,
    calculate_dns_features,
    calculate_time_series_periodicity,
    generate_ja3_fingerprint
)

class TestFeatureEngineering(unittest.TestCase):

    def test_shannon_entropy(self):
        # Uniform string has maximum entropy for its alphabet
        ent_low = calculate_shannon_entropy("aaaaaaa")
        self.assertEqual(ent_low, 0.0)

        ent_high = calculate_shannon_entropy("abcdefghijk")
        self.assertGreater(ent_high, 3.0)

    def test_dns_features(self):
        # Benign domain
        benign = calculate_dns_features("google.com")
        self.assertLess(benign["shannon_entropy"], 3.0)
        self.assertFalse(benign["has_hex_pattern"])

        # DGA domain
        dga = calculate_dns_features("xkqwzpjfvblrmt.com")
        self.assertGreater(dga["shannon_entropy"], 3.5)
        self.assertGreater(dga["consecutive_consonants_max"], 5)

        # DNS Tunnel hex chunk
        tunnel = calculate_dns_features("4a7f9b2c3d1e8a0f5c2b.data.exfil.org")
        self.assertTrue(tunnel["has_hex_pattern"])
        self.assertGreater(tunnel["domain_length"], 25)

    def test_c2_periodicity(self):
        # Strict 2.0s beaconing with minimal jitter
        timestamps = [10.0, 12.01, 13.99, 16.02, 18.00, 20.01, 22.00]
        res = calculate_time_series_periodicity(timestamps)
        
        self.assertTrue(res["is_periodic"])
        self.assertAlmostEqual(res["mean_iat_sec"], 2.0, delta=0.1)
        self.assertLess(res["jitter_cv"], 0.10)
        self.assertGreater(res["periodicity_score"], 0.80)

        # Random Poisson arrivals
        rand_ts = [1.0, 1.4, 5.2, 5.3, 12.1, 14.0]
        rand_res = calculate_time_series_periodicity(rand_ts)
        self.assertFalse(rand_res["is_periodic"])

    def test_ja3_fingerprint(self):
        ja3 = generate_ja3_fingerprint("771", [49195, 49199], [0, 23, 65281], [29, 23], [0])
        self.assertEqual(len(ja3), 32) # MD5 hex string length

if __name__ == "__main__":
    unittest.main()
