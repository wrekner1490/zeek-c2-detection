import sys
from behavioral_analyzer import analyze_behaviors

class CorrelationEngine:
    """
    Combines JA3 context with behavioral math to produce actionable C2 alerts.
    Filters out background noise using structural heuristics.
    """
    def __init__(self, cv_threshold=0.5, min_duration=10.0, min_packets=10):
        # High periodicity = extremely low CV. Meaning StdDev is tiny compared to Mean.
        self.cv_threshold = cv_threshold
        # Mitigates "Short Burst" false positives
        self.min_duration = min_duration 
        # Mitigates low volume false periodicity
        self.min_packets = min_packets
        
    def evaluate(self, behavior, conn_reader=None):
        """Returns (RiskLevel, Classification, ReasonList)"""
        reasons = []
        score = 0
        
        # Derived duration limit checking
        duration = behavior.mean_interval * (behavior.packet_count - 1)
        
        # 1. Periodicity (Behavioral Signal)
        is_periodic = False
        
        # FIX-1: Jitter Evasion Correlation
        if 0.0 <= behavior.cv < self.cv_threshold:
            is_periodic = True
            score += 40
            reasons.append(f"Highly Periodic (CV={behavior.cv:.4f} < {self.cv_threshold})")
        
        if behavior.autocorr > 0.3:
            is_periodic = True
            score += 30
            reasons.append(f"High Autocorrelation (r={behavior.autocorr:.4f})")
            
        if behavior.spectral > 0.4:
            is_periodic = True
            score += 20
            reasons.append(f"Dominant Spectral Frequency (power={behavior.spectral:.4f})")
            
        # FIX-3: Encryption Blindness Byte Scoring
        byte_asymmetry_ratio = 1.0
        packet_size_entropy = 10.0
        if conn_reader and behavior.uids:
            # FIX-4: Non-blocking async cache lookup
            orig_bytes_list = []
            resp_bytes_list = []
            for uid in behavior.uids:
                b_cache = conn_reader.get_bytes(uid)
                if b_cache:
                    orig_bytes_list.append(b_cache["orig_bytes"])
                    resp_bytes_list.append(b_cache["resp_bytes"])
                    
            if orig_bytes_list:
                sum_orig = sum(orig_bytes_list)
                sum_resp = sum(resp_bytes_list)
                if sum_resp > 0:
                    byte_asymmetry_ratio = sum_orig / sum_resp
                else:
                    byte_asymmetry_ratio = 0.0
                    
                import math
                from collections import Counter
                # Shannon entropy of orig_bytes
                counts = Counter(orig_bytes_list)
                total = len(orig_bytes_list)
                entropy = -sum((c/total) * math.log2(c/total) for c in counts.values())
                packet_size_entropy = entropy
                
                if byte_asymmetry_ratio < 0.1:
                    score += 15
                    reasons.append(f"C2 Byte Asymmetry (Upload/Download = {byte_asymmetry_ratio:.4f} < 0.1)")
                if packet_size_entropy < 1.5:
                    score += 15
                    reasons.append(f"Low Packet Size Entropy ({packet_size_entropy:.4f} < 1.5)")
            
        # 2. Volume & Persistence (Confidence Signal)
        if duration >= self.min_duration and behavior.packet_count >= self.min_packets:
            score += 2
            reasons.append(f"Persistent Connection (Duration={duration:.2f}s, Packets={behavior.packet_count})")
            
        # 3. Cryptographic Identity (JA3 Signal)
        if behavior.rarity == "RARE":
            score += 3
            reasons.append(f"Rare JA3 Signature Globally Observed")
        elif behavior.rarity == "UNKNOWN" or behavior.rarity == "MISSING":
            score += 1
            reasons.append(f"Uncommon or Missing Context JA3")
            
        # 4. Consistency Edge Case
        if len(behavior.ja3_seen) > 1:
            score += 1
            reasons.append(f"JA3 Multiplexing/Inconsistency across single flow ({len(behavior.ja3_seen)} hashes)")

        # Evaluate Categories based on composite score rules
        # HIGH Risk requires BOTH Periodicity and either Rarity or heavy persistence.
        if score >= 40 and is_periodic:
            alert_level = "HIGH"
            label = "Likely C2 Beacon"
        elif score >= 20:
            alert_level = "MEDIUM"
            label = "Suspicious Automated Traffic"
        else:
            alert_level = "LOW"
            label = "Normal / Benign Traffic"
            
        # Force downgrade short bursts even if mathematically periodic
        if duration < self.min_duration and alert_level == "HIGH":
            alert_level = "MEDIUM"
            label = "Short Burst Periodic (Downgraded)"
            reasons.append(f"Downgraded from HIGH due to short duration ({duration:.2f}s < {self.min_duration}s)")
            
        return score, alert_level, label, reasons

def run_correlation(log_path):
    print("[*] Launching Phase 5: Correlation Engine...\n")
    
    analyzed_flows, intel_layer = analyze_behaviors(log_path)
    engine = CorrelationEngine(cv_threshold=0.5, min_duration=10.0, min_packets=10)
    
    print("\n" + "="*80)
    print("                  FINAL PHASE 5 ALERT CLASSIFICATIONS")
    print("="*80 + "\n")
    
    results = {"HIGH": [], "MEDIUM": [], "LOW": []}
    
    for b in analyzed_flows:
        score, level, label, reasons = engine.evaluate(b)
        results[level].append((b, label, reasons))
        
    # Output Validation: Print reasoning for classifications
    for level in ["HIGH", "MEDIUM", "LOW"]:
        flows = results[level]
        if not flows:
            continue
            
        # Print all HIGHs and MEDIUMs, but limit LOWs to keep console clean
        limit = len(flows) if level != "LOW" else 3
        
        print(f"[{level} RISK] - {len(flows)} Flows Detected")
        for b, label, reasons in flows[:limit]:
            print(f"  [-] Flow: {b.flow_key}")
            print(f"      Classification : {label}")
            for r in reasons:
                print(f"      -> Reason      : {r}")
            print()
            
        if level == "LOW" and len(flows) > 3:
            print(f"  ... and {len(flows) - 3} more LOW risk flows hidden.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python correlation_engine.py <path_to_ssl.log>")
        sys.exit(1)
        
    log_path = sys.argv[1]
    run_correlation(log_path)
