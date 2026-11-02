import pandas as pd
import numpy as np

def analyze():
    print("--- Loading DNS Log ---")
    dns_path = "data/real_logs/CTU13-Botnet42/dns.log"
    df_dns = pd.read_csv(
        dns_path, 
        sep='\t', 
        comment='#',
        names=[
            'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
            'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 
            'RA', 'Z', 'answers', 'TTLs', 'rejected'
        ],
        on_bad_lines='skip',
        low_memory=False
    )
    df_dns.dropna(subset=['ts', 'id.orig_h'], inplace=True)
    df_dns['ts'] = pd.to_numeric(df_dns['ts'], errors='coerce')
    df_dns['query'] = df_dns['query'].astype(str)
    
    df_dns = df_dns.sort_values(by=['id.orig_h', 'query', 'ts'])
    df_dns['interval'] = df_dns.groupby(['id.orig_h', 'query'])['ts'].diff()
    
    beacon_stats = df_dns.groupby(['id.orig_h', 'query', 'id.resp_h']).agg(
        count=('ts', 'count'),
        mean_interval=('interval', 'mean'),
        std_interval=('interval', 'std'),
        last_ts=('ts', 'last')
    ).reset_index()
    
    beacon_candidates = beacon_stats[beacon_stats['count'] >= 4].copy()
    print(f"1. DNS beacon candidates found before CV filter (>=4 count): {len(beacon_candidates)}")
    
    beacon_candidates['cv'] = beacon_candidates['std_interval'] / beacon_candidates['mean_interval']
    
    print("\n4. Actual CV values for the top 5 most periodic DNS flows (lowest CV):")
    top_5 = beacon_candidates.sort_values('cv').head(5)
    for _, row in top_5.iterrows():
        print(f"   IP: {row['id.orig_h']}, Query: {row['query']}, CV: {row['cv']:.4f}, Count: {row['count']}, Mean Int: {row['mean_interval']:.2f}s")
        
    # Free memory
    del df_dns
    del beacon_stats
    del beacon_candidates
    import gc
    gc.collect()

    print("\n--- Loading Conn Log ---")
    conn_path = "data/real_logs/CTU13-Botnet42/conn.log"
    df_conn = pd.read_csv(
        conn_path, 
        sep='\t', 
        comment='#',
        names=[
            'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
            'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 
            'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
            'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'
        ],
        on_bad_lines='skip',
        low_memory=False
    )
    df_conn.dropna(subset=['ts', 'id.orig_h'], inplace=True)
    df_conn['ts'] = pd.to_numeric(df_conn['ts'], errors='coerce')
    df_conn['duration'] = pd.to_numeric(df_conn['duration'], errors='coerce').fillna(0.0)
    
    long_durations = df_conn[df_conn['duration'] > 300.0]
    print(f"\n2. Conn.log rows exceeding 300s duration: {len(long_durations)}")
    
    pairs = df_conn.groupby(['id.orig_h', 'id.resp_h']).size()
    strobe_candidates = pairs[pairs > 100]
    print(f"\n3. src->dst pairs exceeding 100 connections: {len(strobe_candidates)}")

if __name__ == "__main__":
    analyze()
