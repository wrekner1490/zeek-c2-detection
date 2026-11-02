import pandas as pd
import numpy as np
import math
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Union

@dataclass
class DNSAlert:
    """Dataclass to hold structured DNS alerts."""
    timestamp: float
    src_ip: str
    dst_ip: str # the DNS server queried
    query: str
    alert_type: str # BEACON, TUNNEL, FASTFLUX, DGA
    score: float # 0 - 100
    evidence: dict
    module_name: str = "dns_analyzer"

class DNSAnalyzer:
    """
    RITA-inspired DNS analysis module.
    Detects DNS Beaconing, Tunneling, Fast-Flux, and DGA.
    """
    def __init__(self, entropy_threshold: float = 3.2, cv_threshold: float = 2.5):
        self.entropy_threshold = entropy_threshold
        self.cv_threshold = cv_threshold

    def _shannon_entropy(self, data: str) -> float:
        """Calculates Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _consonant_vowel_ratio(self, domain: str) -> float:
        """Calculates the ratio of consonants to vowels in a domain label."""
        if not domain or domain == '-':
            return 0.0
        
        parts = domain.lower().split('.')
        if len(parts) < 2:
            return 0.0 # Single label domain
            
        label = parts[0]
        
        if len(label) < 8:
            return 0.0
            
        if any(char.isdigit() for char in label):
            return 0.0
            
        vowels = set("aeiouy")
        consonants = set("bcdfghjklmnpqrstvwxz")
        
        v_count = sum(1 for char in label if char in vowels)
        c_count = sum(1 for char in label if char in consonants)
        
        if v_count == 0:
            return float(c_count) if c_count > 0 else 0.0
        return float(c_count) / v_count

    def _parse_dns_log(self, filepath: str) -> pd.DataFrame:
        """Parses a Zeek TSV dns.log into a pandas DataFrame."""
        try:
            df = pd.read_csv(
                filepath, 
                sep='\t', 
                comment='#',
                names=[
                    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                    'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
                    'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 
                    'RA', 'Z', 'answers', 'TTLs', 'rejected'
                ],
                on_bad_lines='skip',
            )
            df.dropna(subset=['ts', 'id.orig_h'], inplace=True)
            df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
            return df
        except Exception as e:
            print(f"[-] Error reading dns.log: {e}")
            return pd.DataFrame()

    def analyze(self, df_or_path: Union[pd.DataFrame, str], ssl_snis: Optional[Set[str]] = None) -> List[DNSAlert]:
        """
        Analyzes a DNS dataframe or file for anomalies.
        ssl_snis: A set of SNIs seen in SSL logs to cross-reference against queries.
        """
        alerts = []
        if isinstance(df_or_path, str):
            df = self._parse_dns_log(df_or_path)
        else:
            df = df_or_path.copy()
            
        if df is None or df.empty:
            return alerts
            
        df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
        df['query'] = df['query'].astype(str)
        df['qtype_name'] = df['qtype_name'].astype(str)
        
        df = df.sort_values(by=['id.orig_h', 'query', 'ts'])
        
        # 1. DNS Beaconing Analysis
        df['interval'] = df.groupby(['id.orig_h', 'query'])['ts'].diff()
        
        beacon_stats = df.groupby(['id.orig_h', 'query', 'id.resp_h']).agg(
            count=('ts', 'count'),
            mean_interval=('interval', 'mean'),
            std_interval=('interval', 'std'),
            last_ts=('ts', 'last')
        ).reset_index()
        
        beacon_candidates = beacon_stats[beacon_stats['count'] >= 3].copy()
        beacon_candidates['cv'] = beacon_candidates['std_interval'] / beacon_candidates['mean_interval']
        
        for _, row in beacon_candidates.iterrows():
            if pd.notna(row['cv']) and row['cv'] < self.cv_threshold and row['mean_interval'] > 0:
                score = 100 - (row['cv'] * 20)
                score = max(50, min(100, score))
                
                cross_ref_penalty = 0
                if ssl_snis is not None and row['query'] not in ssl_snis and row['query'] != '-':
                    cross_ref_penalty = 15
                    score = min(100, score + cross_ref_penalty)
                
                alerts.append(DNSAlert(
                    timestamp=row['last_ts'],
                    src_ip=row['id.orig_h'],
                    dst_ip=row['id.resp_h'],
                    query=row['query'],
                    alert_type="BEACON",
                    score=score,
                    evidence={
                        'cv': round(row['cv'], 4),
                        'mean_interval': round(row['mean_interval'], 2),
                        'count': row['count'],
                        'ssl_sni_missing': cross_ref_penalty > 0
                    }
                ))

        # 3. Fast-Flux Detection
        def parse_fast_flux(group):
            all_ips = set()
            min_ttl = float('inf')
            for _, row in group.iterrows():
                ans = str(row.get('answers', ''))
                ttl = str(row.get('TTLs', ''))
                if ans != '-' and ttl != '-':
                    try:
                        ans_list = [a.strip() for a in ans.split(',') if a.strip()]
                        ttl_list = [float(t) for t in ttl.split(',') if t.strip()]
                        all_ips.update(ans_list)
                        if ttl_list:
                            min_ttl = min(min_ttl, min(ttl_list))
                    except:
                        pass
            return pd.Series({'unique_ips': len(all_ips), 'min_ttl': min_ttl, 'last_ts': group['ts'].max(), 'dst_ip': group['id.resp_h'].iloc[-1]})

        ff_stats = df.groupby(['id.orig_h', 'query']).apply(parse_fast_flux).reset_index()
        for _, row in ff_stats.iterrows():
            if row['query'] == '-' or pd.isna(row['query']):
                continue
            if row['min_ttl'] < 300 and row['unique_ips'] >= 3:
                not_in_ssl = ssl_snis is not None and row['query'] not in ssl_snis
                base_score_bump = 10 if not_in_ssl else 0
                alerts.append(DNSAlert(
                    timestamp=row['last_ts'],
                    src_ip=row['id.orig_h'],
                    dst_ip=row['dst_ip'],
                    query=row['query'],
                    alert_type="FASTFLUX",
                    score=min(100, 80 + base_score_bump),
                    evidence={
                        'min_ttl': row['min_ttl'],
                        'unique_answer_ips': row['unique_ips'],
                        'ssl_sni_missing': not_in_ssl
                    }
                ))

        # We only want to analyze unique queries per src_ip for remaining detections
        latest_queries = df.drop_duplicates(subset=['id.orig_h', 'query'], keep='last')

        for _, row in latest_queries.iterrows():
            q = row['query']
            if q == '-' or pd.isna(q):
                continue
                
            src_ip = row['id.orig_h']
            dst_ip = row['id.resp_h']
            ts = row['ts']
            
            not_in_ssl = ssl_snis is not None and q not in ssl_snis
            base_score_bump = 10 if not_in_ssl else 0

            # 2. DNS Tunneling
            entropy = self._shannon_entropy(q)
            qtype = row['qtype_name']
            if entropy > self.entropy_threshold or (len(q) > 52 and qtype in ['TXT', 'NULL']):
                score = min(100, 75 + (entropy * 5) + base_score_bump)
                alerts.append(DNSAlert(
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    query=q,
                    alert_type="TUNNEL",
                    score=score,
                    evidence={
                        'entropy': round(entropy, 2),
                        'length': len(q),
                        'qtype': qtype,
                        'ssl_sni_missing': not_in_ssl
                    }
                ))

            # 4. DGA Detection
            cv_ratio = self._consonant_vowel_ratio(q)
            if cv_ratio > 4.0:
                score = min(100, 70 + (cv_ratio * 2) + base_score_bump)
                alerts.append(DNSAlert(
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    query=q,
                    alert_type="DGA",
                    score=score,
                    evidence={
                        'cv_ratio': round(cv_ratio, 2),
                        'ssl_sni_missing': not_in_ssl
                    }
                ))

        return alerts
