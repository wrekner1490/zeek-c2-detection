import sys
import json
from collections import defaultdict
from datetime import datetime
from collections import defaultdict

class ZeekSSLRecord:
    """Structured class to hold Zeek SSL log data."""
    def __init__(self, ts, uid, src_ip, dst_ip, dst_port, server_name, ja3):
        # Convert timestamp to a usable float/datetime object if possible
        try:
            self.timestamp = datetime.fromtimestamp(float(ts))
        except (ValueError, TypeError):
            self.timestamp = None
            
        self.uid = uid # FIX-3
        self.source_ip = src_ip
        self.destination_ip = dst_ip
        self.destination_port = dst_port
        self.server_name = server_name if server_name and server_name != '-' else "Unknown"
        self.ja3 = ja3 if ja3 and ja3 != '-' else None

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "server_name": self.server_name,
            "ja3": self.ja3
        }

def process_ja3_data(filepath, tail_mode=False):
    """
    Generator that parses Zeek ssl.log and yields ZeekSSLRecord objects.
    Memory-efficient stream processing with robust log-rotation tailing.
    """
    import os
    import time
    
    while True:
        try:
            if not os.path.exists(filepath):
                if not tail_mode:
                    print(f"[-] Error: File {filepath} not found.")
                    return
                time.sleep(2)  # Wait for file to be created
                continue

            with open(filepath, 'r') as f:
                fields = []
                last_ino = os.stat(filepath).st_ino
                
                while True:
                    cur_pos = f.tell()
                    line = f.readline()
                    
                    if not line:
                        if tail_mode:
                            try:
                                st = os.stat(filepath)
                                # Log rotated (new inode) or truncated (size shrank)
                                if st.st_ino != last_ino or st.st_size < cur_pos:
                                    break  # Break inner loop to close and reopen file
                            except FileNotFoundError:
                                break  # File deleted/moved, break to reopen
                                
                            time.sleep(0.5)
                            continue
                        else:
                            return  # End of batch file
                            
                    line = line.strip()
                    if not line:
                        continue
                
                # Parse Headers
                if line.startswith("#fields"):
                    fields = line.split('\t')[1:]
                    continue
                
                if line.startswith("#"):
                    continue
                
                if not fields:
                    print("[-] Error: Reached data before '#fields' header.")
                    break

                row_values = line.split('\t')
                
                # Graceful handling for malformed lines
                if len(row_values) != len(fields):
                    continue
                    
                record_raw = dict(zip(fields, row_values))

                # Create structured object
                record = ZeekSSLRecord(
                    ts=record_raw.get("ts"),
                    uid=record_raw.get("uid"), # FIX-3
                    src_ip=record_raw.get("id.orig_h"),
                    dst_ip=record_raw.get("id.resp_h"),
                    dst_port=record_raw.get("id.resp_p"),
                    server_name=record_raw.get("server_name"),
                    ja3=record_raw.get("ja3")
                )
                
                yield record
                
            # If we broke out of the inner loop and tail_mode exists, the outer loop reopens it!
            if not tail_mode:
                break
                
        except Exception as e:
            if not tail_mode:
                print(f"[-] Error parsing log: {e}")
                break
            time.sleep(2)  # Backoff and retry on transient fault

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ja3_extractor.py <path_to_ssl.log>")
        sys.exit(1)
        
    log_path = sys.argv[1]
    print(f"[*] Starting Phase 2: Extracting JA3 data from {log_path}\n")
    
    unique_fingerprints = set()
    ja3_global_counts = defaultdict(int)
    ja3_ip_counts = defaultdict(lambda: defaultdict(int))
    sample_records = []
    total_records = 0
    
    for record in process_ja3_data(log_path):
        total_records += 1
        
        if record.ja3:
            unique_fingerprints.add(record.ja3)
            ja3_global_counts[record.ja3] += 1
            ja3_ip_counts[record.source_ip][record.ja3] += 1
            
        if len(sample_records) < 3:
            sample_records.append(record)
    
    if total_records > 0:
        print(f"[+] Successfully parsed {total_records} TLS records.")
        print(f"[+] Found {len(unique_fingerprints)} unique JA3 fingerprints.\n")
        
        print("[*] Sample Extracted Records (First 3):")
        for rec in sample_records:
            print(f"    {json.dumps(rec.to_dict())}")
            
        print("\n[*] Top 10 JA3 Fingerprints observed globally:")
        for ja3, count in sorted(ja3_global_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"    - {ja3} (Seen {count} times)")
            
        print("\n[*] Sample of JA3 frequency per Source IP:")
        ip_sample = 0
        for ip, counts in ja3_ip_counts.items():
            if ip_sample >= 3: break
            print(f"    [IP: {ip}]")
            for ja3, count in counts.items():
                print(f"        -> {ja3}: {count} times")
            ip_sample += 1
        
        if len(unique_fingerprints) > 10:
            print(f"\n    ... and {len(unique_fingerprints) - 10} more hashes tracked.")
            
    else:
        print("[-] No valid records extracted.")
