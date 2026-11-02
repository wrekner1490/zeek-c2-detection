import pandas as pd
from modules.long_conn import LongConnectionAnalyzer
from modules.strobe_detector import StrobeDetector
from modules.dns_analyzer import DNSAnalyzer

ip = "147.32.84.165"
print(f"--- Analyzing {ip} ---")

# 1. Long Conn
print("\n[LONG CONN]")
conn_path = "data/real_logs/CTU13-Botnet43/conn.log"
df_conn = pd.read_csv(conn_path, sep='\t', comment='#', names=['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'])
df_conn['duration'] = pd.to_numeric(df_conn['duration'], errors='coerce').fillna(0.0)
df_conn['orig_bytes'] = pd.to_numeric(df_conn['orig_bytes'], errors='coerce').fillna(0)
df_conn['resp_bytes'] = pd.to_numeric(df_conn['resp_bytes'], errors='coerce').fillna(0)

long_detector = LongConnectionAnalyzer()
long_alerts = long_detector.analyze(df_conn)
my_long_alerts = [a for a in long_alerts if getattr(a, 'src_ip', '') == ip]
print(f"Long Conn Alerts for {ip}: {len(my_long_alerts)}")
for a in my_long_alerts:
    print("  ", a)

# 2. Strobe
print("\n[STROBE]")
strobe_detector = StrobeDetector()
strobe_alerts = strobe_detector.analyze(df_conn)
my_strobe_alerts = [a for a in strobe_alerts if getattr(a, 'src_ip', '') == ip]
print(f"Strobe Alerts for {ip}: {len(my_strobe_alerts)}")
for a in my_strobe_alerts:
    print("  ", a)

# 3. DNS
print("\n[DNS]")
dns_path = "data/real_logs/CTU13-Botnet43/dns.log"
df_dns = pd.read_csv(dns_path, sep='\t', comment='#', names=['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected'])

dns_analyzer = DNSAnalyzer()
dns_alerts = dns_analyzer.analyze(df_dns)
my_dns_alerts = [a for a in dns_alerts if getattr(a, 'src_ip', '') == ip]
print(f"DNS Alerts for {ip}: {len(my_dns_alerts)}")
for a in my_dns_alerts:
    print("  ", a)
