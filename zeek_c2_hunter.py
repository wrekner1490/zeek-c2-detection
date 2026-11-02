import sys
import argparse
import json
import csv
import time
from behavioral_analyzer import analyze_behaviors
from ja3_intelligence import classify_ja3

# ANSI Color Codes for SOC visibility
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class CorrelationEngine:
    """
    Combines JA3 context with behavioral math to produce actionable C2 alerts.
    Filters out background noise using structural heuristics.
    """
    def __init__(self, cv_threshold=0.5, min_duration=10.0, min_packets=10):
        self.cv_threshold = cv_threshold
        self.min_duration = min_duration 
        self.min_packets = min_packets
        
    def evaluate(self, behavior):
        """Returns (RiskLevel, Score, Duration, ClassificationLabel, ReasonList)"""
        reasons = []
        score = 0
        
        # Derived duration limit checking
        duration = behavior.mean_interval * (behavior.packet_count - 1)
        
        # 1. Periodicity (Behavioral Signal)
        is_periodic = False
        if 0.0 <= behavior.cv < self.cv_threshold:
            is_periodic = True
            score += 3
            reasons.append(f"Highly Periodic (CV={behavior.cv:.4f} < {self.cv_threshold})")
        elif behavior.cv < (self.cv_threshold * 2):
            score += 1
            reasons.append(f"Semi-Periodic (CV={behavior.cv:.4f})")
            
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

        # Evaluate Categories
        if score >= 6 and is_periodic:
            alert_level = "HIGH"
            label = "Likely C2 Beacon"
        elif score >= 4:
            alert_level = "MEDIUM"
            label = "Suspicious Automated Traffic"
        else:
            alert_level = "LOW"
            label = "Normal / Benign Traffic"
            
        # Downgrade short bursts
        if duration < self.min_duration and alert_level == "HIGH":
            alert_level = "MEDIUM"
            label = "Short Burst Periodic (Downgraded)"
            reasons.append(f"Downgraded from HIGH due to short duration ({duration:.2f}s < {self.min_duration}s)")
            
        return alert_level, score, duration, label, reasons

def main():
    parser = argparse.ArgumentParser(description="Zeek JA3 C2 Behavioral Hunter (Production SOC Engine)")
    parser.add_argument("--input", "-i", required=True, help="Path to input Zeek ssl.log")
    parser.add_argument("--output", "-o", choices=["json", "csv", "both", "none"], default="none", help="File export format")
    parser.add_argument("--min-alert", "-m", choices=["LOW", "MEDIUM", "HIGH"], default="MEDIUM", help="Minimum alert severity to display/export")
    parser.add_argument("--top", "-t", type=int, default=0, help="Limit output to Top N alerts (0 = all)")
    parser.add_argument("--sort", "-s", choices=["score", "duration"], default="score", help="Sort alerts before limiting")
    
    args = parser.parse_args()
    
    severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    min_sev_val = severity_map[args.min_alert.upper()]
    
    print(f"{Colors.BOLD}{Colors.BLUE}[*] Launching C2 Hunter (Phase 6){Colors.RESET}")
    start_time = time.time()
    
    # Run intelligence -> behavior math silently
    analyzed_flows, intel_layer = analyze_behaviors(args.input)
    engine = CorrelationEngine(cv_threshold=0.5, min_duration=10.0, min_packets=10)
    
    # Generate structured alerts
    alerts_structured = []
    
    for b in analyzed_flows:
        level, score, duration, label, reasons = engine.evaluate(b)
        
        if severity_map[level] < min_sev_val:
            continue
            
        ja3_list = list(b.ja3_seen)
        # Re-derive standard classification from Phase 3 intel
        primary_class = classify_ja3(ja3_list[0]) if ja3_list else "MISSING"
        if len(ja3_list) > 1:
            primary_class = "MIXED"
            
        # Create dict structure matching JSON requirement
        alert_obj = {
            "src_ip": b.src_ip,
            "dst_ip": b.dst_ip,
            "dst_port": b.dst_port,
            "sni": b.sni,
            "packet_count": b.packet_count,
            "duration": round(duration, 2),
            "mean_interval": round(b.mean_interval, 4),
            "cv": round(b.cv, 4),
            "ja3_classification": primary_class,
            "ja3_list": list(b.ja3_seen),
            "ja3_rarity": b.rarity,
            "score": score,
            "alert_level": level,
            "reasons": reasons
        }
        alerts_structured.append(alert_obj)
        
    # Sorting Output
    if args.sort == "score":
        alerts_structured.sort(key=lambda x: x["score"], reverse=True)
    elif args.sort == "duration":
        alerts_structured.sort(key=lambda x: x["duration"], reverse=True)
        
    # Apply Limit
    if args.top > 0:
        alerts_structured = alerts_structured[:args.top]
        
    # --- CONSOLE OUTPUT ---
    print("\n" + "="*80)
    print(f"                  {Colors.BOLD}FINAL C2 DETECTIONS DETECTED{Colors.RESET}")
    print("="*80 + "\n")
    
    for alert in alerts_structured:
        c = Colors.GREEN
        if alert["alert_level"] == "HIGH": c = Colors.RED
        elif alert["alert_level"] == "MEDIUM": c = Colors.YELLOW
        
        print(f"{Colors.BOLD}{c}[{alert['alert_level']} RISK - Score {alert['score']}]{Colors.RESET} - {alert['src_ip']} -> {alert['dst_ip']}:{alert['dst_port']} (SNI: {alert['sni']})")
        print(f"      Duration: {alert['duration']}s | Packets: {alert['packet_count']} | CV: {alert['cv']}")
        print(f"      JA3 Rarity: {alert['ja3_rarity']} | Hashes: {len(alert['ja3_list'])}")
        for r in alert["reasons"]:
            print(f"      -> {r}")
        print()
        
    # --- LOGGING STATISTICS ---
    process_time = time.time() - start_time
    total_high = sum(1 for a in alerts_structured if a['alert_level'] == 'HIGH')
    total_med = sum(1 for a in alerts_structured if a['alert_level'] == 'MEDIUM')
    total_low = sum(1 for a in alerts_structured if a['alert_level'] == 'LOW')
    
    print(f"{Colors.BOLD}[*] Execution Summary:{Colors.RESET}")
    print(f"    - Processing Time: {process_time:.2f}s")
    print(f"    - Flows Analyzed : {len(analyzed_flows)}")
    print(f"    - Alerts Generated (>= {args.min_alert}): {len(alerts_structured)}")
    
    if args.output in ["json", "both"]:
        with open("alerts.json", "w") as jf:
            json.dump(alerts_structured, jf, indent=4)
        print(f"{Colors.GREEN}[+] Wrote structured alerts to alerts.json{Colors.RESET}")
        
    if args.output in ["csv", "both"]:
        if alerts_structured:
            headers = list(alerts_structured[0].keys())
            # Convert list of reasons to string for CSV
            for row in alerts_structured:
                row["reasons"] = " | ".join(row["reasons"])
            
            with open("alerts.csv", "w", newline='') as cf:
                writer = csv.DictWriter(cf, fieldnames=headers)
                writer.writeheader()
                writer.writerows(alerts_structured)
            print(f"{Colors.GREEN}[+] Wrote structured alerts to alerts.csv{Colors.RESET}")

if __name__ == "__main__":
    # Prevent print pollution from upstream modules
    # A cleaner SOC tool shouldn't have raw info dumped before CLI
    import behavioral_analyzer
    behavioral_analyzer.analyze_behaviors = behavioral_analyzer.analyze_behaviors
    main()
