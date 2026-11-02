import pandas as pd
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Union

@dataclass
class LongConnAlert:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: str
    uid: str
    alert_type: str  # LONG_CONN, IDLE_C2, EXFILTRATION, LOW_AND_SLOW
    score: float
    evidence: dict
    module_name: str = "long_conn"

class LongConnectionAnalyzer:
    """
    Analyzes conn.log for unusually long durations, idle C2 channels,
    data exfiltration (asymmetric upload), and persistent low-and-slow connections.
    """
    def __init__(self, long_duration_threshold: float = 120.0, 
                 idle_bytes_threshold: int = 50000,
                 persistence_count_threshold: int = 50,
                 persistence_duration_threshold: float = 60.0):
        self.long_duration_threshold = long_duration_threshold
        self.idle_bytes_threshold = idle_bytes_threshold
        self.persistence_count_threshold = persistence_count_threshold
        self.persistence_duration_threshold = persistence_duration_threshold

    def _parse_conn_log(self, filepath: str) -> pd.DataFrame:
        try:
            df = pd.read_csv(
                filepath, 
                sep='\t', 
                comment='#',
                names=[
                    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                    'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 
                    'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
                    'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'
                ],
                on_bad_lines='skip',
            )
            df.dropna(subset=['ts', 'id.orig_h'], inplace=True)
            df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
            df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0.0)
            df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
            df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)
            return df
        except Exception as e:
            print(f"[-] Error reading conn.log: {e}")
            return pd.DataFrame()

    def analyze(self, df_or_path: Union[pd.DataFrame, str], flagged_beacon_uids: Optional[Set[str]] = None) -> List[LongConnAlert]:
        alerts = []
        if isinstance(df_or_path, str):
            df = self._parse_conn_log(df_or_path)
        else:
            df = df_or_path.copy()
            
        if df is None or df.empty:
            return alerts
            
        df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0.0)
        df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
        df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)
        
        # We need a fallback uid if not provided
        if 'uid' not in df.columns:
            df['uid'] = 'unknown'

        flagged_uids = flagged_beacon_uids or set()

        # 1. Single Connection Anomalies
        for _, row in df.iterrows():
            duration = row['duration']
            orig_bytes = row['orig_bytes']
            resp_bytes = row['resp_bytes']
            uid = row['uid']
            
            is_beacon = uid in flagged_uids
            base_multiplier = 1.5 if is_beacon else 1.0

            # A) Idle C2 & Long Connection
            if duration > self.long_duration_threshold:
                total_bytes = orig_bytes + resp_bytes
                
                if total_bytes < self.idle_bytes_threshold:
                    score = min(100, 75 * base_multiplier)
                    alerts.append(LongConnAlert(
                        timestamp=row['ts'], src_ip=row['id.orig_h'], dst_ip=row['id.resp_h'],
                        dst_port=str(row['id.resp_p']), uid=uid, alert_type="IDLE_C2",
                        score=score,
                        evidence={'duration': duration, 'total_bytes': total_bytes, 'is_beacon': is_beacon}
                    ))
                else:
                    score = min(100, 60 * base_multiplier)
                    alerts.append(LongConnAlert(
                        timestamp=row['ts'], src_ip=row['id.orig_h'], dst_ip=row['id.resp_h'],
                        dst_port=str(row['id.resp_p']), uid=uid, alert_type="LONG_CONN",
                        score=score,
                        evidence={'duration': duration, 'total_bytes': total_bytes, 'is_beacon': is_beacon}
                    ))

            # B) Asymmetric Upload (Exfiltration)
            # Threshold: uploaded at least 10x more than downloaded, min 1MB uploaded
            if orig_bytes > (resp_bytes * 10) and orig_bytes > 1000000:
                score = min(100, 80 * base_multiplier)
                alerts.append(LongConnAlert(
                    timestamp=row['ts'], src_ip=row['id.orig_h'], dst_ip=row['id.resp_h'],
                    dst_port=str(row['id.resp_p']), uid=uid, alert_type="EXFILTRATION",
                    score=score,
                    evidence={'orig_bytes': orig_bytes, 'resp_bytes': resp_bytes, 'ratio': round(orig_bytes/max(1,resp_bytes), 2)}
                ))

        # 2. Low-and-Slow Persistence (Aggregated over 1 hour window)
        # Using a simplified window approximation: assume df is roughly a 1-hour window
        agg_stats = df.groupby(['id.orig_h', 'id.resp_h']).agg(
            conn_count=('ts', 'count'),
            mean_duration=('duration', 'mean'),
            last_ts=('ts', 'max')
        ).reset_index()

        for _, row in agg_stats.iterrows():
            if row['conn_count'] > self.persistence_count_threshold and row['mean_duration'] > self.persistence_duration_threshold:
                alerts.append(LongConnAlert(
                    timestamp=row['last_ts'], src_ip=row['id.orig_h'], dst_ip=row['id.resp_h'],
                    dst_port="*", uid="*", alert_type="LOW_AND_SLOW",
                    score=70.0,
                    evidence={'conn_count': row['conn_count'], 'mean_duration': round(row['mean_duration'], 2)}
                ))

        return alerts
