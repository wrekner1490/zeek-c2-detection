import os
import csv
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Set, Optional

# Attempt to use the existing monotonic timer, fallback if not found
try:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from flow_timer import FlowTimer
    _timer = FlowTimer()
    get_time = _timer.elapsed_seconds
except ImportError:
    get_time = time.monotonic

@dataclass
class ThreatIntelAlert:
    timestamp: float
    src_ip: str
    indicator: str
    match_type: str # EXACT_IP, DOMAIN, SUBNET, DOMAIN_SUFFIX
    score: float
    evidence: dict
    module_name: str = "threat_intel"

class ThreatIntelChecker:
    """
    Cross-references IPs and domains against loaded threat intelligence feeds.
    Applies multi-host amplification scoring.
    """
    def __init__(self, cache_ttl: float = 3600.0):
        self.cache_ttl = cache_ttl
        self.last_load_time = 0.0
        
        self.bad_ips: Set[str] = set()
        self.bad_domains: Set[str] = set()
        self.bad_subnets_24: Set[str] = set()
        
        # Track which internal hosts contacted which bad indicator for amplification
        self.indicator_to_hosts = defaultdict(set)

    def load_feed(self, filepath: str):
        """Loads a text file or Abuse.ch CSV feed."""
        if not os.path.exists(filepath):
            print(f"[-] Threat intel feed not found: {filepath}")
            return

        now = get_time()
        if (now - self.last_load_time) < self.cache_ttl and self.last_load_time > 0:
            return # Cache is fresh

        print(f"[*] Loading Threat Intel from {filepath}...")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Basic sniff to see if it's Abuse.ch CSV
                first_line = f.readline()
                f.seek(0)
                
                if "urlhaus" in first_line.lower() or 'id,"dateadded"' in first_line.lower():
                    # Abuse.ch format
                    reader = csv.reader((line for line in f if not line.startswith('#')))
                    for row in reader:
                        if len(row) > 2:
                            url = row[2] # URL usually in col 3
                            # very crude extraction for demo
                            host = url.split('/')[2].split(':')[0] if '//' in url else url
                            if host.replace('.','').isdigit():
                                self.bad_ips.add(host)
                                self._add_subnet(host)
                            else:
                                self.bad_domains.add(host)
                else:
                    # Plain list format (one per line)
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if line.replace('.','').isdigit():
                            self.bad_ips.add(line)
                            self._add_subnet(line)
                        else:
                            self.bad_domains.add(line)
                            
            self.last_load_time = get_time()
            print(f"[+] Loaded {len(self.bad_ips)} IPs and {len(self.bad_domains)} domains.")
        except Exception as e:
            print(f"[-] Error loading threat feed: {e}")

    def _add_subnet(self, ip: str):
        parts = ip.split('.')
        if len(parts) == 4:
            self.bad_subnets_24.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")

    def _get_subnet(self, ip: str) -> str:
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""

    def analyze_contact(self, src_ip: str, dst_ip: str, domain: Optional[str] = None, timestamp: float = 0.0) -> Optional[ThreatIntelAlert]:
        """Analyzes a single connection for threat intel hits."""
        score = 0.0
        match_type = ""
        indicator = ""
        
        # 1. Exact IP match
        if dst_ip in self.bad_ips:
            score = 100.0
            match_type = "EXACT_IP"
            indicator = dst_ip
        # 2. Domain Match
        elif domain and domain in self.bad_domains:
            score = 80.0
            match_type = "DOMAIN"
            indicator = domain
        # 3. Subnet /24 Match
        elif self._get_subnet(dst_ip) in self.bad_subnets_24:
            score = 60.0
            match_type = "SUBNET"
            indicator = self._get_subnet(dst_ip)
        # 4. Domain Suffix Match
        elif domain:
            for bad_dom in self.bad_domains:
                if domain.endswith("." + bad_dom):
                    score = 40.0
                    match_type = "DOMAIN_SUFFIX"
                    indicator = bad_dom
                    break

        if score > 0:
            self.indicator_to_hosts[indicator].add(src_ip)
            
            # Multi-host amplification: if 3+ hosts contacted this, amplify
            amplified = False
            if len(self.indicator_to_hosts[indicator]) >= 3:
                score = min(100.0, score * 1.5)
                amplified = True
                
            return ThreatIntelAlert(
                timestamp=timestamp,
                src_ip=src_ip,
                indicator=indicator,
                match_type=match_type,
                score=score,
                evidence={'hosts_contacted': len(self.indicator_to_hosts[indicator]), 'amplified': amplified}
            )
            
        return None
