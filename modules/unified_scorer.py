from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from collections import defaultdict

@dataclass
class HostRiskProfile:
    src_ip: str
    unified_score: float = 0.0
    # Individual highest scores per module
    beacon_score: float = 0.0
    dns_score: float = 0.0
    long_conn_score: float = 0.0
    strobe_score: float = 0.0
    threat_intel_score: float = 0.0
    ja3_score: float = 0.0
    
    # Evidence tracking
    top_reasons: List[str] = field(default_factory=list)
    module_breakdown: dict = field(default_factory=dict)

class UnifiedScorer:
    """
    Combines all module scores into a single host risk score.
    Weights: Beacon (25%), DNS (15%), Long Conn (25%), Threat Intel (5%), Strobe (25%), JA3 (5%).
    """
    def __init__(self):
        self.weights = {
            'beacon': 0.25,
            'dns': 0.15,
            'long_conn': 0.25,
            'threat_intel': 0.05,
            'strobe': 0.25,
            'ja3': 0.05
        }
        self.host_profiles: Dict[str, HostRiskProfile] = {}

    def _get_profile(self, src_ip: str) -> HostRiskProfile:
        if src_ip not in self.host_profiles:
            self.host_profiles[src_ip] = HostRiskProfile(src_ip=src_ip)
        return self.host_profiles[src_ip]

    def add_beacon_alert(self, src_ip: str, score: float, reason: str):
        p = self._get_profile(src_ip)
        p.beacon_score = max(p.beacon_score, score)
        p.top_reasons.append(f"[BEACON] {reason}")

    def add_dns_alert(self, src_ip: str, score: float, reason: str):
        p = self._get_profile(src_ip)
        p.dns_score = max(p.dns_score, score)
        p.top_reasons.append(f"[DNS] {reason}")

    def add_long_conn_alert(self, src_ip: str, score: float, reason: str):
        p = self._get_profile(src_ip)
        p.long_conn_score = max(p.long_conn_score, score)
        p.top_reasons.append(f"[LONG_CONN] {reason}")

    def add_strobe_alert(self, src_ip: str, score: float, reason: str):
        p = self._get_profile(src_ip)
        p.strobe_score = max(p.strobe_score, score)
        p.top_reasons.append(f"[STROBE] {reason}")

    def add_threat_intel_alert(self, src_ip: str, score: float, reason: str):
        p = self._get_profile(src_ip)
        p.threat_intel_score = max(p.threat_intel_score, score)
        p.top_reasons.append(f"[THREAT_INTEL] {reason}")

    def add_ja3_alert(self, src_ip: str, score: float, reason: str):
        p = self._get_profile(src_ip)
        p.ja3_score = max(p.ja3_score, score)
        p.top_reasons.append(f"[JA3] {reason}")

    def compute_all_scores(self) -> List[HostRiskProfile]:
        """Calculates unified score and returns ranked list descending."""
        for ip, p in self.host_profiles.items():
            p.unified_score = (
                (p.beacon_score * self.weights['beacon']) +
                (p.dns_score * self.weights['dns']) +
                (p.long_conn_score * self.weights['long_conn']) +
                (p.threat_intel_score * self.weights['threat_intel']) +
                (p.strobe_score * self.weights['strobe']) +
                (p.ja3_score * self.weights['ja3'])
            )
            
            p.module_breakdown = {
                'beacon': p.beacon_score,
                'dns': p.dns_score,
                'long_conn': p.long_conn_score,
                'threat_intel': p.threat_intel_score,
                'strobe': p.strobe_score,
                'ja3': p.ja3_score
            }
            
            # Keep only unique and highest impact reasons
            # (simplified cleanup for demo)
            p.top_reasons = list(set(p.top_reasons))[:5]
            
        return sorted(list(self.host_profiles.values()), key=lambda x: x.unified_score, reverse=True)
