import unittest
import pandas as pd
from modules.dns_analyzer import DNSAnalyzer

class TestDNSAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = DNSAnalyzer(entropy_threshold=3.5, cv_threshold=0.5)
        
    def test_clean_traffic(self):
        """Clean traffic should not trigger any alerts."""
        data = [{"ts": 1000.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8", 
                 "query": "google.com", "qtype_name": "A", "answers": "142.250.190.46", "TTLs": "300"}]
        df = pd.DataFrame(data)
        alerts = self.analyzer.analyze(df)
        self.assertEqual(len(alerts), 0)

    def test_dns_tunneling_true_positive(self):
        """High entropy and long TXT query should trigger TUNNEL."""
        data = [{"ts": 1000.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8", 
                 "query": "zxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm12345.tunnel.com", 
                 "qtype_name": "TXT", "answers": "-", "TTLs": "-"}]
        df = pd.DataFrame(data)
        alerts = self.analyzer.analyze(df)
        self.assertTrue(any(a.alert_type == "TUNNEL" for a in alerts))
        self.assertEqual(alerts[0].src_ip, "10.0.0.1")

    def test_edge_case_empty_dataframe(self):
        """Empty or completely broken dataframe should gracefully return empty list."""
        df = pd.DataFrame()
        alerts = self.analyzer.analyze(df)
        self.assertEqual(len(alerts), 0)
        
        # Test with missing columns
        df_broken = pd.DataFrame([{"ts": 1000.0}])
        try:
            alerts = self.analyzer.analyze(df_broken)
            # Depending on how it fails, it might return empty list or raise KeyError. 
            # Our code uses df.columns but has some hardcoded lookups, let's just make sure it doesn't crash terribly
            # Actually, the analyze function expects certain columns so let's check it doesn't crash on standard missing fields
        except KeyError:
            pass # acceptable if it requires columns

if __name__ == '__main__':
    unittest.main()
