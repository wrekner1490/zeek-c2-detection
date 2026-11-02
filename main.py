import argparse
from zeek_c2_hunter_live import live_monitor

def main():
    parser = argparse.ArgumentParser(description="Zeek C2 Detection Pipeline (RITA-Inspired)")
    parser.add_argument("--ssl", required=True, help="Path to Zeek ssl.log (Required for JA3 tracking)")
    parser.add_argument("--conn", help="Path to Zeek conn.log (For Long Conn and Strobe Detection)")
    parser.add_argument("--dns", help="Path to Zeek dns.log (For DNS Tunneling, Fast-Flux, DGA)")
    parser.add_argument("--threat-intel-file", help="Path to Threat Intel CSV or TXT file")
    parser.add_argument("--output", choices=["json", "csv", "console"], default="console", help="Output format (default: console)")
    parser.add_argument("--report", action="store_true", help="Generate an HTML SOC dashboard report")
    parser.add_argument("--min-score", type=float, default=20.0, help="Minimum unified risk score to report")
    
    # Internal options mapped for the live_monitor
    parser.add_argument("--live", action="store_true", help="Tail the files continuously (live mode)")
    parser.add_argument("--window", type=int, default=0, help="Batch evaluation interval in seconds")
    parser.add_argument("--baseline", action="store_true", help="Learn baseline connections")
    parser.add_argument("--baseline-freeze", action="store_true", help="Enforce baseline without learning")
    parser.add_argument("--baseline-reset", action="store_true", help="Reset existing baseline")

    args = parser.parse_args()
    
    # Map --ssl to --input for backward compatibility with the existing engine
    args.input = args.ssl
    
    if args.output == "json":
        args.stdout_json = True
    else:
        args.stdout_json = False

    print("[*] Starting Zeek-C2-Detection Main Pipeline...")
    live_monitor(args)

if __name__ == "__main__":
    main()
