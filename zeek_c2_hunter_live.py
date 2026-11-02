import sys
import time
import json
import hashlib
import argparse
import signal
from pathlib import Path

from ja3_extractor import process_ja3_data
from ja3_intelligence import JA3Intelligence
from behavioral_analyzer import FlowBehavior
from correlation_engine import CorrelationEngine

# Newly added modules for fixes
from baseline_validator import BaselineValidator
from conn_log_reader import ConnLogReader
from flow_state_manager import FlowStateManager

# New RITA-Inspired Modules
from modules.dns_analyzer import DNSAnalyzer
from modules.long_conn import LongConnectionAnalyzer
from modules.strobe_detector import StrobeDetector
from modules.threat_intel import ThreatIntelChecker
from modules.unified_scorer import UnifiedScorer
from output.report_generator import generate_html_report

# ANSI Color Codes for SOC visibility
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class ConfigLoader:
    @staticmethod
    def load(filepath="config.yaml"):
        # Ideally this would parse the YAML, but for now we update the hardcoded defaults
        # based on real CTU-13 dataset tuning
        config = {
            "cv_threshold": 2.5,      # Raised from 0.7 to accommodate extremely high jitter in Neris scenario 43
            "min_packets": 3,         # Lowered from 10/4
            "min_duration": 10.0,
            "rarity_threshold": 0.001,
            "enrichment_enabled": True,
            "mock_asn_db": {
                "amazon.com": "AS16509 (Amazon.com)",
                "s3.amazonaws.com": "AS16509 (Amazon.com)",
                "cloudflare.com": "AS13335 (Cloudflare)",
                "azure.com": "AS8075 (Microsoft)"
            },
            "mock_geo_db": {
                "10.": "Local LAN",
                "192.168.": "Local LAN",
                "172.16.": "Local LAN"
            },
            "dedup_window": 3600
        }
        return config

class AlertDeduplicator:
    def __init__(self, window_seconds):
        self.window = window_seconds
        self.history = {}
        
    def should_alert(self, flow_key, ja3_str):
        fingerprint = hashlib.md5(f"{flow_key}_{ja3_str}".encode()).hexdigest()
        now = time.monotonic()
        
        if fingerprint in self.history:
            if (now - self.history[fingerprint]) < self.window:
                return False
                
        self.history[fingerprint] = now
        return True
        
    def cleanup(self):
        now = time.monotonic()
        expired = [k for k, v in self.history.items() if (now - v) > self.window]
        for k in expired:
            del self.history[k]

class Enricher:
    def __init__(self, config):
        self.enabled = config["enrichment_enabled"]
        self.asn = config["mock_asn_db"]
        self.geo = config["mock_geo_db"]
        
    def enrich(self, sni, dst_ip):
        if not self.enabled:
            return "Unknown ASN", "Unknown Geo"
            
        asn_res = "Unknown ASN"
        geo_res = "External Route"
        
        for k,v in self.asn.items():
            if sni and k in sni:
                asn_res = v
                break
                
        for k,v in self.geo.items():
            if dst_ip.startswith(k):
                geo_res = v
                break
                
        return asn_res, geo_res

def live_monitor(args):
    config = ConfigLoader.load()
    intel = JA3Intelligence(rare_percentage_threshold=config["rarity_threshold"])
    engine = CorrelationEngine(cv_threshold=config["cv_threshold"], 
                               min_duration=config["min_duration"], 
                               min_packets=config["min_packets"])
                               
    dedup = AlertDeduplicator(config["dedup_window"])
    enricher = Enricher(config)
    
    baseline = BaselineValidator("baseline.json")
    if args.baseline_reset:
        if Path(baseline.path).exists(): Path(baseline.path).unlink()
        if Path(baseline.sha_path).exists(): Path(baseline.sha_path).unlink()
        
    baseline.load_baseline()
    
    state_manager = FlowStateManager()
    restored = state_manager.restore(max_age=3600)
    intel.flows.update(restored)
    
    conn_log_path = getattr(args, 'conn', 'conn.log')
    conn_reader = ConnLogReader(filepath=conn_log_path, tail_mode=args.live)
    conn_reader.start()

    # Initialize RITA Modules
    dns_analyzer = DNSAnalyzer()
    long_conn_analyzer = LongConnectionAnalyzer()
    strobe_detector = StrobeDetector()
    threat_intel = ThreatIntelChecker()
    unified_scorer = UnifiedScorer()
    
    if args.threat_intel_file:
        threat_intel.load_feed(args.threat_intel_file)

    if not args.stdout_json:
        print(f"{Colors.BOLD}{Colors.BLUE}[*] Starting C2 Live Monitor with Unified Scoring (Phase 8){Colors.RESET}")
        print(f"    - SSL Log: {args.input}")
        print(f"    - DNS Log: {getattr(args, 'dns', 'None')}")
        print(f"    - Conn Log: {getattr(args, 'conn', 'conn.log')}")
        print(f"    - Tailing: {args.live}")
        print(f"    - Restored flows: {len(restored)}\n")

    def sigterm_handler(signum, frame):
        if not args.stdout_json: print("\n[*] Received SIGTERM/SIGINT, flushing state and exiting...")
        state_manager.stop(lambda: intel.flows)
        conn_reader.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)
    
    state_manager.start_checkpointing(lambda: intel.flows, interval=60)
    
    last_eval_time = time.monotonic()
    last_gc_time = time.monotonic()
    batch_window = args.window if args.window else 0
    records_processed = 0

    for record in process_ja3_data(args.input, tail_mode=args.live):
        intel.ingest_record(record)
        records_processed += 1
        
        now = time.monotonic()
        
        eval_interval = batch_window if batch_window > 0 else 10
        if (now - last_eval_time) > eval_interval:
            _evaluate_active_flows(intel, engine, dedup, enricher, baseline, conn_reader, args,
                                   dns_analyzer, long_conn_analyzer, strobe_detector, threat_intel, unified_scorer)
            last_eval_time = now
            
        if (now - last_gc_time) > 300:
            wall_now_estimate = time.time()
            dead_flows = [k for k, v in intel.flows.items() if (v.last_timestamp and (wall_now_estimate - v.last_timestamp) > 3600)]
            for k in dead_flows: del intel.flows[k]
            dedup.cleanup()
            last_gc_time = now

    # Final evaluation
    _evaluate_active_flows(intel, engine, dedup, enricher, baseline, conn_reader, args,
                           dns_analyzer, long_conn_analyzer, strobe_detector, threat_intel, unified_scorer)
    
    if args.baseline:
        baseline.save_baseline()
        if not args.stdout_json:
            print(f"{Colors.GREEN}[+] Baseline updated with {len(baseline.db)} flow fingerprints.{Colors.RESET}")
            
    state_manager.stop(lambda: intel.flows)
    conn_reader.stop()

def _evaluate_active_flows(intel, engine, dedup, enricher, baseline, conn_reader, args,
                           dns_analyzer, long_conn_analyzer, strobe_detector, threat_intel, unified_scorer):
    
    ssl_snis = set()
    flagged_beacon_uids = set()

    # 1. Evaluate SSL Beacons natively
    for key, f_data in intel.flows.items():
        if f_data.sni: ssl_snis.add(f_data.sni)
        
        if f_data.count < 4: continue
        behavior = FlowBehavior(key, f_data, intel)
        ja3_str = list(behavior.ja3_seen)[0] if behavior.ja3_seen else "MISSING"
        fingerprint = hashlib.md5(f"{key}_{ja3_str}".encode()).hexdigest()
        
        if args.baseline and not args.baseline_freeze:
            baseline.track_and_validate(fingerprint, behavior.sni, behavior.src_ip)
            continue
            
        score, level, label, reasons = engine.evaluate(behavior, conn_reader)
        
        if level in ["HIGH", "MEDIUM"]:
            if baseline.is_known(fingerprint):
                if level == "HIGH":
                    level = "MEDIUM"
                else:
                    continue
            
            # Use the actual correlation score capped at 100
            final_score = min(100.0, float(score))
            
            unified_scorer.add_beacon_alert(behavior.src_ip, final_score, f"SSL Beacon to {behavior.dst_ip}")
            flagged_beacon_uids.update(f_data.uids)
            
            # Feed to Threat Intel
            ti_alert = threat_intel.analyze_contact(behavior.src_ip, behavior.dst_ip, domain=behavior.sni, timestamp=time.time())
            if ti_alert:
                unified_scorer.add_threat_intel_alert(ti_alert.src_ip, ti_alert.score, f"TI Hit: {ti_alert.indicator}")

            # Legacy CLI Output (only if dedup passes)
            if dedup.should_alert(key, ja3_str) and not args.stdout_json:
                asn, geo = enricher.enrich(behavior.sni, behavior.dst_ip)
                c = Colors.RED if level == "HIGH" else Colors.YELLOW
                print(f"{c}[{level} BEACON ALERT]{Colors.RESET} {key}")
                for r in reasons: print(f"  -> {r}")

    # 2. Run new analytical modules
    if hasattr(args, 'dns') and args.dns:
        dns_alerts = dns_analyzer.analyze(args.dns, ssl_snis=ssl_snis)
        for a in dns_alerts:
            unified_scorer.add_dns_alert(a.src_ip, a.score, f"{a.alert_type}: {a.query}")

    conn_log = getattr(args, 'conn', 'conn.log')
    if Path(conn_log).exists():
        long_conn_alerts = long_conn_analyzer.analyze(conn_log, flagged_beacon_uids=flagged_beacon_uids)
        for a in long_conn_alerts:
            unified_scorer.add_long_conn_alert(a.src_ip, a.score, f"{a.alert_type} to {a.dst_ip}")
            
        strobe_alerts = strobe_detector.analyze(conn_log)
        for a in strobe_alerts:
            if not a.asn_suppressed:
                unified_scorer.add_strobe_alert(a.src_ip, a.score, f"{a.strobe_type} to {a.dst_ip}")

    # 3. Print Final Risk Rankings
    ranked_hosts = unified_scorer.compute_all_scores()
    
    if args.stdout_json:
        # Dump the top hosts
        for host in ranked_hosts:
            if host.unified_score > getattr(args, 'min_score', 20.0):
                print(json.dumps({
                    "src_ip": host.src_ip,
                    "unified_score": round(host.unified_score, 2),
                    "top_reasons": host.top_reasons,
                    "module_breakdown": host.module_breakdown
                }))
    else:
        # Only print high risk for console output, and avoid spamming
        reportable = [h for h in ranked_hosts if h.unified_score > getattr(args, 'min_score', 20.0)]
        if reportable:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[!] Unified Host Risk Rankings:{Colors.RESET}")
            for host in reportable:
                print(f"    - IP: {host.src_ip} | Risk Score: {host.unified_score:.1f}/100")
                for reason in host.top_reasons:
                    print(f"        * {reason}")
            print()

    if hasattr(args, 'report') and args.report:
        generate_html_report(ranked_hosts)

    import os
    os.makedirs('output', exist_ok=True)
    report_data = []
    for host in ranked_hosts:
        report_data.append({
            'src_ip': getattr(host, 'src_ip', getattr(host, 'ip', None)),
            'unified_risk_score': getattr(host, 'unified_risk_score', getattr(host, 'unified_score', getattr(host, 'score', 0))),
            'modules_fired': getattr(host, 'modules_fired', getattr(host, 'alerts', getattr(host, 'module_breakdown', []))),
            'top_reason': getattr(host, 'top_reason', getattr(host, 'reasons', getattr(host, 'top_reasons', '')))
        })
    with open('output/report.json', 'w') as f:
        json.dump(report_data, f, indent=2, default=str)
    print("[+] Results saved to output/report.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", required=True, help="Path to ssl.log")
    parser.add_argument("--conn", help="Path to conn.log")
    parser.add_argument("--dns", help="Path to dns.log")
    parser.add_argument("--threat-intel-file", help="Path to TI CSV or txt")
    parser.add_argument("--min-score", type=float, default=20.0, help="Minimum unified score to report")
    parser.add_argument("--live", action="store_true", help="Tail the file continuously resiliently")
    parser.add_argument("--window", type=int, default=0, help="Batch schedule interval in seconds")
    parser.add_argument("--baseline", action="store_true", help="Run in learning mode to document normal traffic")
    parser.add_argument("--baseline-freeze", action="store_true", help="Use baseline but do not add new traffic (Read-only)")
    parser.add_argument("--baseline-reset", action="store_true", help="Clear the existing baseline database before start")
    parser.add_argument("--stdout-json", action="store_true", help="Format all output purely as JSON Lines for SIEMs")
    
    args = parser.parse_args()
    live_monitor(args)
