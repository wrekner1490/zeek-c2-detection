import os
import time

def create_dirs():
    os.makedirs('data/sample_logs', exist_ok=True)
    os.makedirs('feeds', exist_ok=True)
    os.makedirs('tests', exist_ok=True)

def write_conn_log():
    header = "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
    header += "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
    header += "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n"
    
    with open('data/sample_logs/conn.log', 'w') as f:
        f.write(header)
        base_ts = 1700000000.0
        
        # 1. Normal traffic (web browsing)
        f.write(f"{base_ts}\tC_norm1\t192.168.1.10\t50001\t8.8.8.8\t53\tudp\tdns\t0.01\t45\t90\tSF\t-\t-\t0\tDd\t1\t73\t1\t118\t-\n")
        f.write(f"{base_ts+2.0}\tC_norm2\t192.168.1.10\t50002\t1.1.1.1\t443\ttcp\tssl\t2.5\t1500\t8500\tSF\t-\t-\t0\tShADadFf\t10\t2000\t15\t9000\t-\n")
        
        # 2. Long Idle C2 Connection (>300s, low bytes)
        f.write(f"{base_ts+10.0}\tC_long1\t192.168.1.11\t50003\t198.51.100.1\t443\ttcp\tssl\t3600.0\t500\t200\tS1\t-\t-\t0\tShA\t5\t800\t3\t400\t-\n")
        
        # 3. Exfiltration (Long conn, high asymmetric bytes)
        f.write(f"{base_ts+20.0}\tC_exfil1\t192.168.1.12\t50004\t198.51.100.2\t443\ttcp\tssl\t400.0\t5000000\t1000\tSF\t-\t-\t0\tShADadFf\t5000\t5100000\t10\t1500\t-\n")

        # 4. Strobe (Connection Flood: >100 conns to 198.51.100.3)
        for i in range(120):
            f.write(f"{base_ts+30.0+(i*0.5)}\tC_strobe_{i}\t192.168.1.13\t{50100+i}\t198.51.100.3\t80\ttcp\thttp\t0.1\t100\t200\tSF\t-\t-\t0\tShADadFf\t3\t250\t3\t350\t-\n")

        # 5. Low and slow (60 conns over 1 hour, avg duration >60s)
        for i in range(60):
            f.write(f"{base_ts+3600.0+(i*65.0)}\tC_lowslow_{i}\t192.168.1.14\t{51000+i}\t198.51.100.4\t443\ttcp\tssl\t65.0\t200\t200\tSF\t-\t-\t0\tShADadFf\t5\t400\t5\t400\t-\n")

def write_dns_log():
    header = "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
    header += "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\n"
    header += "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool\n"
    
    with open('data/sample_logs/dns.log', 'w') as f:
        f.write(header)
        base_ts = 1700000000.0
        
        # 1. Normal traffic
        f.write(f"{base_ts}\tD_norm1\t192.168.1.10\t50001\t8.8.8.8\t53\tudp\t1\t0.01\tgoogle.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t142.250.190.46\t300\tF\n")
        
        # 2. DNS Beaconing (Low CV, every 60s)
        for i in range(10):
            ts = base_ts + (i * 60.0) + (i % 2 * 0.1) # tiny jitter
            f.write(f"{ts}\tD_beacon_{i}\t192.168.1.11\t{52000+i}\t8.8.8.8\t53\tudp\t{2+i}\t0.02\tevil-c2.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t198.51.100.99\t300\tF\n")

        # 3. DNS Tunneling (High entropy, TXT)
        f.write(f"{base_ts+1000.0}\tD_tunnel1\t192.168.1.12\t53000\t8.8.8.8\t53\tudp\t100\t0.05\tzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm.tunnel.com\t1\tC_INTERNET\t16\tTXT\t0\tNOERROR\tF\tF\tT\tT\t0\t-\t-\tF\n")
        
        # 4. Fast-Flux (TTL < 300, 3+ IPs)
        f.write(f"{base_ts+2000.0}\tD_ff1\t192.168.1.13\t54000\t8.8.8.8\t53\tudp\t200\t0.03\tfastflux.com\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t1.1.1.1,2.2.2.2,3.3.3.3\t60,60,60\tF\n")

def write_ssl_log():
    header = "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
    header += "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\tlast_alert\tnext_protocol\testablished\tcert_chain_fuids\tclient_cert_chain_fuids\tsubject\tissuer\tclient_subject\tclient_issuer\tvalidation_status\tja3\tja3s\n"
    header += "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\tstring\tstring\tbool\tvector[string]\tvector[string]\tstring\tstring\tstring\tstring\tstring\tstring\tstring\n"
    
    with open('data/sample_logs/ssl.log', 'w') as f:
        f.write(header)
        base_ts = 1700000000.0
        
        # 1. Normal traffic (google.com)
        f.write(f"{base_ts}\tS_norm1\t192.168.1.10\t50002\t1.1.1.1\t443\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\tsecp256r1\tgoogle.com\tF\t-\t-\tT\t-\t-\t-\t-\t-\t-\t-\tcd08e31494f9531f560d64c695473da9\t-\n")
        
        # 2. SSL Beaconing (Matches long idle and threat intel)
        # 192.168.1.11 to 198.51.100.1 every 60s
        for i in range(10):
            ts = base_ts + (i * 60.0) + (i % 2 * 0.1)
            # JA3 for python requests
            f.write(f"{ts}\tS_beacon_{i}\t192.168.1.11\t{55000+i}\t198.51.100.1\t443\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\tsecp256r1\tmalware.com\tF\t-\t-\tT\t-\t-\t-\t-\t-\t-\t-\t3b5074b1b5d032e5620f69f9f700ff0e\t-\n")

def write_threat_intel():
    with open('feeds/abuse_ch.csv', 'w') as f:
        f.write("# Abuse.ch URLhaus Database\n")
        f.write("id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n")
        f.write("1,2023-01-01,http://198.51.100.1:80/evil.exe,online,malware_download,exe,https://...,reporter\n")
        f.write("2,2023-01-01,http://evil-c2.com/c2,online,c2,c2,https://...,reporter\n")

if __name__ == "__main__":
    create_dirs()
    write_conn_log()
    write_dns_log()
    write_ssl_log()
    write_threat_intel()
    print("Test data generated successfully!")
