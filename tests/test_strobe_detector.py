import unittest
import pandas as pd
from modules.strobe_detector import StrobeDetector

class TestStrobeDetector(unittest.TestCase):
    def setUp(self):
        self.detector = StrobeDetector(strobe_threshold=100)
        
    def test_clean_traffic(self):
        """Normal traffic should not trigger strobe."""
        data = [{"ts": 1000.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8", "id.resp_p": 443} for _ in range(5)]
        df = pd.DataFrame(data)
        alerts = self.detector.analyze(df)
        self.assertEqual(len(alerts), 0)

    def test_strobe_true_positive(self):
        """101 connections should trigger a strobe alert."""
        data = [{"ts": 1000.0 + i, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8", "id.resp_p": 443} for i in range(105)]
        df = pd.DataFrame(data)
        alerts = self.detector.analyze(df)
        self.assertTrue(any(a.strobe_type == "CONNECTION_FLOOD" for a in alerts))
        self.assertFalse(alerts[0].asn_suppressed)

    def test_edge_case_cdn_suppression(self):
        """Strobe to CDN should be flagged but suppressed (or scored lower)."""
        # 104.16.x.x is mock Cloudflare in our DB
        data = [{"ts": 1000.0 + i, "id.orig_h": "10.0.0.1", "id.resp_h": "104.16.1.1", "id.resp_p": 443} for i in range(105)]
        df = pd.DataFrame(data)
        alerts = self.detector.analyze(df)
        self.assertTrue(alerts[0].asn_suppressed)
        self.assertLess(alerts[0].score, 50.0) # Suppressed score should be low

if __name__ == '__main__':
    unittest.main()
