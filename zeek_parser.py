import sys
import json

def parse_zeek_log(filepath):
    """
    Minimal script to read a Zeek log (e.g., ssl.log) line by line.
    It extracts field names from the #fields header and maps each row.
    """
    try:
        with open(filepath, 'r') as f:
            fields = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parse Headers
                if line.startswith("#fields"):
                    fields = line.split('\t')[1:]
                    print(f"[*] Detected Fields: {fields}")
                    continue
                
                # Skip other comments
                if line.startswith("#"):
                    continue
                
                # Parse Data Rows
                if not fields:
                    print("[-] Error: Reached data before '#fields' header. Is this a valid Zeek TSV log?")
                    return

                row_values = line.split('\t')
                
                # Create dictionary mapping field names to values
                record = dict(zip(fields, row_values))
                
                # Extract requested fields for validation
                extracted_info = {
                    "timestamp": record.get("ts"),
                    "source_ip": record.get("id.orig_h"),
                    "destination_ip": record.get("id.resp_h"),
                    "server_name": record.get("server_name"),
                    "ja3": record.get("ja3")
                }
                print(f"[DATA] {json.dumps(extracted_info)}")
                
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
    except Exception as e:
        print(f"[-] Error parsing log: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python zeek_parser.py <path_to_ssl.log>")
        sys.exit(1)
        
    log_path = sys.argv[1]
    print(f"[*] Starting Phase 1: Parsing Zeek log -> {log_path}")
    parse_zeek_log(log_path)
