import pandas as pd
dns_path = "data/real_logs/CTU13-Botnet43/dns.log"
df = pd.read_csv(dns_path, sep='\t', comment='#', names=['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs', 'rejected'])

df = df[df['id.orig_h'] == '147.32.84.165']
df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
df['query'] = df['query'].astype(str)
df = df.sort_values(by=['query', 'ts'])
df['interval'] = df.groupby(['query'])['ts'].diff()

stats = df.groupby(['query']).agg(
    count=('ts', 'count'),
    mean_interval=('interval', 'mean'),
    std_interval=('interval', 'std')
).reset_index()

stats['cv'] = stats['std_interval'] / stats['mean_interval']
print(stats.sort_values(by='count', ascending=False).head(20))
