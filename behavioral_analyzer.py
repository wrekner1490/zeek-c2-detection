import sys
import math
import numpy as np
from ja3_intelligence import JA3Intelligence, process_ja3_data

class FlowBehavior:
    """Stores the mathematically derived behavioral profile for a flow."""
    def __init__(self, flow_key, flow_data, intel_layer):
        self.flow_key = flow_key
        self.src_ip = flow_data.src_ip
        self.dst_ip = flow_data.dst_ip
        self.dst_port = flow_data.dst_port
        self.sni = flow_data.sni
        self.packet_count = flow_data.count
        
        self.mean_interval = 0.0
        self.variance = 0.0
        self.std_dev = 0.0
        self.cv = 0.0
        
        # FIX-1: Jitter Evasion
        self.autocorr = 0.0
        self.spectral = 0.0
        
        # FIX-3: Ensure encryption blindness uses uids
        self.uids = flow_data.uids
        
        self.ja3_seen = flow_data.ja3_seen
        # Determine overall rarity for the flow based on observed JA3s
        # If any JA3 used in this flow is RARE globally, mark the flow as RARE JA3 usage
        self.rarity = "COMMON"
        self.ja3_classifications = set()
        for ja3 in self.ja3_seen:
            r = intel_layer.get_rarity(ja3)
            # Classification lookup (using intel_layer or global function)
            # We'll import the classify_ja3 logic from phase 3 or just attach it.
            if r == "RARE":
                self.rarity = "RARE"
            elif r == "MID" and self.rarity == "COMMON":
                self.rarity = "MID"

        self._compute_stats(flow_data)

    def _compute_stats(self, data):
        """Derives valid periodicity metrics using Welford's base data from Phase 3."""
        valid_intervals = data.count - 1
        
        # We enforce a minimum of 3 intervals (4 packets) for statistical trust
        if valid_intervals >= 3:
            self.mean_interval = data.sum_intervals / valid_intervals
            
            # Variance = E[X^2] - (E[X])^2
            mean_of_squares = data.sum_squared_intervals / valid_intervals
            var = mean_of_squares - (self.mean_interval ** 2)
            
            # Prevent tiny floating point negatives
            self.variance = max(0.0, var)
            self.std_dev = math.sqrt(self.variance)
            
            if self.mean_interval > 0:
                self.cv = self.std_dev / self.mean_interval
            else:
                self.cv = 0.0
                
            # FIX-1: Jitter Evasion Signals
            if len(data.intervals) >= 8:
                x = np.array(data.intervals)
                mean = np.mean(x)
                var_sum = np.sum((x - mean)**2)
                if var_sum > 0:
                    self.autocorr = float(np.sum((x[:-1] - mean) * (x[1:] - mean)) / var_sum)
                else:
                    self.autocorr = 0.0
                    
                fft_vals = np.abs(np.fft.fft(x - mean))
                fft_sum = np.sum(fft_vals)
                if fft_sum > 0:
                    self.spectral = float(np.max(fft_vals) / fft_sum)
                else:
                    self.spectral = 0.0
        else:
            self.mean_interval = -1
            self.variance = -1
            self.std_dev = -1
            self.cv = -1
            self.autocorr = -1
            self.spectral = -1

    def is_statistically_valid(self):
        return self.packet_count >= 4

def analyze_behaviors(log_path):
    """Orchestrates Phase 2, 3, and 4."""
    # Run Phase 3 Intelligence Layer
    intel = JA3Intelligence(rare_percentage_threshold=0.001)
    
    print(f"[*] Extracting Intelligence and Grouping Flows from {log_path}...")
    for record in process_ja3_data(log_path):
        intel.ingest_record(record)
        
    print(f"[+] Flow Grouping Complete. Found {len(intel.flows)} total flows.")
    print(f"[*] Starting Phase 4: Behavioral Math Computations...\n")
    
    analyzed_flows = []
    skipped_flows = 0
    
    for key, f_data in intel.flows.items():
        behavior = FlowBehavior(key, f_data, intel)
        if behavior.is_statistically_valid():
            analyzed_flows.append(behavior)
        else:
            skipped_flows += 1
            
    print(f"[+] Computed behavioral statistics for {len(analyzed_flows)} flows.")
    print(f"[!] Skipped {skipped_flows} flows purely due to low packet volume (N < 4).\n")
    
    # Validation Requirement: Print computed stats for each flow (Sample up to 10 for console)
    print("[*] Sample of Computed Flow Behaviors:")
    for b in analyzed_flows[:10]:
        ja3_list = list(b.ja3_seen) if b.ja3_seen else ["MISSING"]
        short_ja3 = ja3_list[0][:8] + "..." if ja3_list[0] != "MISSING" else "MISSING"
        if len(ja3_list) > 1: short_ja3 += " (MULTIPLE)"
        
        print(f"    - Flow: {b.flow_key}")
        print(f"      Packets: {b.packet_count} | JA3 Rarity: {b.rarity} | JA3: {short_ja3}")
        print(f"      Mean Interval: {b.mean_interval:.4f}s | StdDev: {b.std_dev:.4f}s | CV: {b.cv:.4f}\n")
        
    return analyzed_flows, intel

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python behavioral_analyzer.py <path_to_ssl.log>")
        sys.exit(1)
        
    log_path = sys.argv[1]
    analyze_behaviors(log_path)
