import unittest
from modules.threat_intel import ThreatIntelChecker

class TestThreatIntel(unittest.TestCase):
    def setUp(self):
        self.ti = ThreatIntelChecker()
        self.ti.bad_ips.add("198.51.100.99")
        self.ti.bad_domains.add("evil.com")
        
    def test_clean_traffic(self):
        """Benign IP should not trigger alert."""
        alert = self.ti.analyze_contact("10.0.0.1", "8.8.8.8", "google.com")
        self.assertIsNone(alert)

    def test_true_positive_ip(self):
        """Bad IP should trigger an EXACT_IP match."""
        alert = self.ti.analyze_contact("10.0.0.1", "198.51.100.99", "unknown.com")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.match_type, "EXACT_IP")

    def test_edge_case_amplification(self):
        """Three distinct hosts contacting the same bad domain should trigger 1.5x amplification."""
        alert1 = self.ti.analyze_contact("10.0.0.1", "8.8.8.8", "evil.com")
        self.assertFalse(alert1.evidence['amplified'])
        
        alert2 = self.ti.analyze_contact("10.0.0.2", "8.8.8.8", "evil.com")
        self.assertFalse(alert2.evidence['amplified'])
        
        # 3rd host triggers amplification
        alert3 = self.ti.analyze_contact("10.0.0.3", "8.8.8.8", "evil.com")
        self.assertTrue(alert3.evidence['amplified'])
        self.assertGreater(alert3.score, alert1.score)

if __name__ == '__main__':
    unittest.main()
