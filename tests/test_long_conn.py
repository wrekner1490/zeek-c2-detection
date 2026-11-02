import unittest
import pandas as pd
from modules.long_conn import LongConnectionAnalyzer

class TestLongConnAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = LongConnectionAnalyzer()
        
    def test_clean_traffic(self):
        """Short connection should not trigger long conn alerts."""
        data = [{"ts": 1000.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8", 
                 "id.resp_p": 443, "duration": 10.0, "orig_bytes": 100, "resp_bytes": 100, "uid": "C_clean"}]
        df = pd.DataFrame(data)
        alerts = self.analyzer.analyze(df)
        self.assertEqual(len(alerts), 0)

    def test_exfiltration_true_positive(self):
        """Asymmetric large upload should trigger EXFILTRATION."""
        data = [{"ts": 1000.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8", 
                 "id.resp_p": 443, "duration": 400.0, "orig_bytes": 5000000, "resp_bytes": 1000, "uid": "C_exfil"}]
        df = pd.DataFrame(data)
        alerts = self.analyzer.analyze(df)
        self.assertTrue(any(a.alert_type == "EXFILTRATION" for a in alerts))

    def test_edge_case_missing_bytes(self):
        """Duration is long but bytes are NaN or missing."""
        data = [{"ts": 1000.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8", 
                 "id.resp_p": 443, "duration": 400.0, "orig_bytes": None, "resp_bytes": None, "uid": "C_nan"}]
        df = pd.DataFrame(data)
        alerts = self.analyzer.analyze(df)
        # Should be handled gracefully, likely flagging as IDLE_C2 due to 0 bytes
        self.assertTrue(any(a.alert_type == "IDLE_C2" for a in alerts))

if __name__ == '__main__':
    unittest.main()
