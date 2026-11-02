import unittest
from modules.unified_scorer import UnifiedScorer

class TestUnifiedScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = UnifiedScorer()
        
    def test_clean_traffic(self):
        """No alerts should result in 0 score."""
        scores = self.scorer.compute_all_scores()
        self.assertEqual(len(scores), 0)

    def test_true_positive_accumulation(self):
        """Multiple alerts should accumulate correctly into a single score."""
        self.scorer.add_beacon_alert("10.0.0.1", 100.0, "Beaconing")
        self.scorer.add_dns_alert("10.0.0.1", 100.0, "Tunneling")
        
        scores = self.scorer.compute_all_scores()
        self.assertEqual(len(scores), 1)
        # Beacon (35%) + DNS (20%) of 100 = 55.0
        self.assertAlmostEqual(scores[0].unified_score, 55.0)

    def test_edge_case_highest_score_wins(self):
        """If a module triggers multiple times, the highest score should be retained, not summed over 100."""
        self.scorer.add_strobe_alert("10.0.0.2", 50.0, "Small Strobe")
        self.scorer.add_strobe_alert("10.0.0.2", 90.0, "Big Strobe")
        
        scores = self.scorer.compute_all_scores()
        self.assertEqual(len(scores), 1)
        # Strobe is 10% weight. 90.0 * 0.10 = 9.0
        self.assertAlmostEqual(scores[0].unified_score, 9.0)
        self.assertEqual(scores[0].strobe_score, 90.0)

if __name__ == '__main__':
    unittest.main()
