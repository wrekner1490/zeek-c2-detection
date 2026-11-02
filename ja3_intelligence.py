import sys
from collections import defaultdict
from ja3_extractor import process_ja3_data

# Small known-good JA3 database (Examples of common browsers/tools)
KNOWN_JA3_HASHES = {
    # Typical Chrome
    "cd08e31494f9531f560d64c695473da9": "Chrome/Edge",
    "771ff321fc00201b23ad7612f0fc98be": "Chrome/Edge",
    "b32309a26951912be7dba376398abc3b": "Chrome/Edge",
    # Typical Firefox
    "72a589da586844d7f0818ce684948eea": "Firefox",
    "1eaaf6260cf1c0b39690fe4fed1600f9": "Firefox",
    # macOS/iOS Safari
    "85eb5ba800c1440afce25251412b1d7d": "Safari",
    # Python requests/urllib
    "3b5074b1b5d032e5620f69f9f700ff0e": "Python Requests",
    "e7d705a3286e19ea42f587b344ee6865": "Python Requests"
}

def classify_ja3(ja3_hash):
    """Classify a JA3 hash as MISSING, KNOWN, or UNKNOWN."""
    if not ja3_hash or ja3_hash == "-":
        return "MISSING"
    if ja3_hash in KNOWN_JA3_HASHES:
        return "KNOWN"
    return "UNKNOWN"

class FlowData:
    """Stores behavioral preparation aggregates via rolling statistics for a given flow."""
    def __init__(self, src_ip, dst_ip, dst_port, sni):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.sni = sni
        
        self.count = 0
        self.last_timestamp = None
        self.sum_intervals = 0.0
        self.sum_squared_intervals = 0.0
        self.ja3_seen = set()
        self.intervals = [] # FIX-1
        self.uids = [] # FIX-3
        
    def add_record(self, record):
        self.count += 1
        
        if record.ja3:
            self.ja3_seen.add(record.ja3)
            
        # FIX-3: Extract UIDs for Encryption Blindness lookup
        if getattr(record, 'uid', None):
            self.uids.append(record.uid)
            
        if record.timestamp:
            ts_float = record.timestamp.timestamp()
            if self.last_timestamp is not None:
                interval = ts_float - self.last_timestamp
                # FIX-1: Jitter Evasion, store bounded intervals
                self.intervals.append(interval)
                if len(self.intervals) > 50:
                    self.intervals.pop(0)
                    
                self.sum_intervals += interval
                self.sum_squared_intervals += (interval ** 2)
            self.last_timestamp = ts_float

class JA3Intelligence:
    def __init__(self, rare_percentage_threshold=0.001):
        self.rare_threshold = rare_percentage_threshold
        self.total_records = 0
        
        # Frequency trackers
        self.global_ja3_counts = defaultdict(int)
        self.ja3_to_ips = defaultdict(set)
        self.ip_to_ja3s = defaultdict(lambda: defaultdict(int))
        
        # Behavioral preparation
        self.flows = {}

    def ingest_record(self, record):
        """Processes a single ZeekSSLRecord without storing it permanently."""
        self.total_records += 1
        ja3 = record.ja3
        
        # 1. Update frequencies
        if ja3:
            self.global_ja3_counts[ja3] += 1
            self.ja3_to_ips[ja3].add(record.source_ip)
            self.ip_to_ja3s[record.source_ip][ja3] += 1
            
        # 2. Behavioral preparation per flow
        sni = record.server_name if record.server_name else "None"
        dst_port = getattr(record, 'destination_port', "None")
        flow_key = f"{record.source_ip} -> {record.destination_ip}:{dst_port} (SNI:{sni})"
        
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowData(record.source_ip, record.destination_ip, dst_port, sni)
            
        self.flows[flow_key].add_record(record)
        
    def get_rarity(self, ja3_hash):
        """Returns RARE if occurrence percentage is below threshold globally, else COMMON/MID."""
        if not ja3_hash or self.total_records == 0:
            return "MISSING"
        count = self.global_ja3_counts.get(ja3_hash, 0)
        percentage = count / self.total_records
        
        if percentage < self.rare_threshold:
            return "RARE"
        elif percentage > (self.rare_threshold * 50): # Arbitrary definition of high freq
            return "COMMON"
        else:
            return "MID"

    def analyze(self):
        """Performs end-of-stream aggregations and prints validation metrics."""
        
        # Separate JA3s for summary
        rare_ja3s = {j: c for j, c in self.global_ja3_counts.items() if self.get_rarity(j) == "RARE"}
        common_ja3s = {j: c for j, c in self.global_ja3_counts.items() if self.get_rarity(j) == "COMMON"}
        
        top_10_ja3 = sorted(self.global_ja3_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        print("[+] Phase 3 Intelligence Summary\n")
        
        # Validation 1: Show top 10 most common JA3
        print("[*] Top 10 Most Common JA3 Fingerprints:")
        for ja3, count in top_10_ja3:
            cls = classify_ja3(ja3)
            ips_count = len(self.ja3_to_ips[ja3])
            print(f"    - {ja3} | Class: {cls} | Freq: {count} | Unique IPs: {ips_count}")
            
        # Validation 2: Show rare JA3 list (limit to 10 for console cleanup)
        print("\n[*] Rare JA3 Fingerprints List:")
        rare_items = sorted(rare_ja3s.items(), key=lambda x: x[1])
        if not rare_items:
            print("    [None found]")
        for ja3, count in rare_items[:10]:
            cls = classify_ja3(ja3)
            ips_count = len(self.ja3_to_ips[ja3])
            perc = (count / self.total_records) * 100
            print(f"    - {ja3} | Class: {cls} | Freq: {count} ({perc:.4f}%) | Unique IPs: {ips_count}")
        if len(rare_items) > 10:
            print(f"    ... and {len(rare_items) - 10} more rare profiles.")
            
        # Validation 3: Show at least 3 example IPs with their JA3 distribution
        print("\n[*] Sample Source IPs and their JA3 distributions:")
        ip_sample = 0
        for ip, counts in self.ip_to_ja3s.items():
            if ip_sample >= 3: break
            print(f"    [IP: {ip}]")
            for ja3, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
                cls = classify_ja3(ja3)
                rarity = self.get_rarity(ja3)
                print(f"        -> {ja3} | {cls} | {rarity} | Saw: {count} times")
            ip_sample += 1
            
        # Validation 4: Confirm handling of missing JA3
        missing_count = sum(1 for flow in self.flows.values() if not flow.ja3_seen)
        print(f"\n[*] Found {missing_count} flows containing only MISSING JA3 hashes (Safely skipped in correlation).")

        # Validation 6: Behavioral prep snippet
        print("\n[*] Flow Preparation Sample (Behavorial readiness):")
        flow_sample = 0
        for flow_key, f_data in self.flows.items():
            if flow_sample >= 3: break
            ja3_cons = list(f_data.ja3_seen)[:2]  # Show up to 2
            cons_str = f"{len(f_data.ja3_seen)} unique JA3s used" if f_data.ja3_seen else "MISSING JA3"
            
            # Simulated rolling stat intervals computation to prove it works
            mean_int = f_data.sum_intervals / f_data.count if f_data.count > 0 else 0
            
            print(f"    - Flow: {flow_key}\n        Packets: {f_data.count} | Consistency: {cons_str} | Sum Intervals: {f_data.sum_intervals:.2f}s | Mean Interval: {mean_int:.4f}s")
            flow_sample += 1
            
        print(f"\n[*] Total Unique Flows Grouped: {len(self.flows)}")
        print(f"[*] Total Records Processed: {self.total_records}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ja3_intelligence.py <path_to_ssl.log>")
        sys.exit(1)
        
    log_path = sys.argv[1]
    intel = JA3Intelligence(rare_percentage_threshold=0.001)  # 0.1%
    
    print(f"[*] Starting Phase 3: Processing {log_path} through Intelligence Layer...")
    
    # Ingest directly from Phase 2 generator
    for record in process_ja3_data(log_path):
        intel.ingest_record(record)
        
    intel.analyze()
