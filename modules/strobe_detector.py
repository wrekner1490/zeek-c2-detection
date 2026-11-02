import pandas as pd
from dataclasses import dataclass
from typing import List, Optional, Union

@dataclass
class StrobeAlert:
    timestamp: float
    src_ip: str
    dst_ip: str
    strobe_type: str  # CONNECTION_FLOOD, PORT_SCAN
    conn_count: int
    asn_suppressed: bool
    score: float
    evidence: dict
    module_name: str = "strobe_detector"

class StrobeDetector:
    """
    Detects hosts making an unusually high number of connections
    to a single IP, while applying CDN/ASN suppression to avoid FPs.
    Also detects port scanning behavior.
    """
    def __init__(self, strobe_threshold: int = 50, port_scan_threshold: int = 20):
        self.strobe_threshold = strobe_threshold
        self.port_scan_threshold = port_scan_threshold
        
        # Mock ASN database for CDN suppression
        self.mock_asn_db = {
            "104.16.0.0/12": "Cloudflare",
            "13.32.0.0/15": "Amazon",
            "52.239.0.0/16": "Azure"
        }
        # Simplified IP string matching for mock purposes
        self.cdn_ips = ["104.16", "13.32", "13.33", "52.239"]

    def _is_cdn(self, ip: str) -> bool:
        """Checks if an IP belongs to a known CDN using mock matching."""
        return any(ip.startswith(prefix) for prefix in self.cdn_ips)

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
            return df
        except Exception as e:
            print(f"[-] Error reading conn.log: {e}")
            return pd.DataFrame()

    def analyze(self, df_or_path: Union[pd.DataFrame, str]) -> List[StrobeAlert]:
        alerts = []
        if isinstance(df_or_path, str):
            df = self._parse_conn_log(df_or_path)
        else:
            df = df_or_path.copy()
            
        if df is None or df.empty:
            return alerts
            
        df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
        df['ts_dt'] = pd.to_datetime(df['ts'], unit='s')
        df = df.sort_values('ts_dt')
        
        # Group by src, dst, and 1-hour time bins
        rolling_stats = df.groupby(['id.orig_h', 'id.resp_h', pd.Grouper(key='ts_dt', freq='1h')]).agg(
            conn_count=('ts', 'count'),
            unique_ports=('id.resp_p', 'nunique')
        ).reset_index()
        
        # Get the maximum count and unique ports for each pair across any 1-hour bin
        stats = rolling_stats.groupby(['id.orig_h', 'id.resp_h']).agg(
            conn_count=('conn_count', 'max'),
            unique_ports=('unique_ports', 'max'),
            last_ts=('ts_dt', 'max')
        ).reset_index()
        
        # Convert last_ts back to float timestamp for the alert
        stats['last_ts'] = stats['last_ts'].astype('int64') / 10**9

        for _, row in stats.iterrows():
            src = row['id.orig_h']
            dst = row['id.resp_h']
            count = row['conn_count']
            ports = row['unique_ports']
            
            is_cdn = self._is_cdn(dst)
            
            # A) Port Scanning
            if ports > self.port_scan_threshold:
                score = 30.0 if is_cdn else 80.0
                alerts.append(StrobeAlert(
                    timestamp=row['last_ts'],
                    src_ip=src, dst_ip=dst, strobe_type="PORT_SCAN",
                    conn_count=count, asn_suppressed=is_cdn, score=score,
                    evidence={'unique_ports': ports, 'total_conns': count, 'cdn': is_cdn}
                ))
            
            # B) Connection Flood (Strobe)
            elif count > self.strobe_threshold:
                score = 25.0 if is_cdn else 75.0
                alerts.append(StrobeAlert(
                    timestamp=row['last_ts'],
                    src_ip=src, dst_ip=dst, strobe_type="CONNECTION_FLOOD",
                    conn_count=count, asn_suppressed=is_cdn, score=score,
                    evidence={'total_conns': count, 'unique_ports': ports, 'cdn': is_cdn}
                ))

        return alerts
