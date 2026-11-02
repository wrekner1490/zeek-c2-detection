import json
import hashlib
import sys
import os

# FIX-2: Baseline Poisoning and SHA256 integrity check
class BaselineValidator:
    def __init__(self, path="baseline.json"):
        self.path = path
        self.sha_path = f"{path}.sha256"
        self.db = set()
        self.sni_origins = {}  # SNI -> set of src_ips

    def load_baseline(self):
        if not os.path.exists(self.path):
            self.db = set()
            return self.db
            
        if not os.path.exists(self.sha_path):
            sys.stderr.write(f"CRITICAL WARNING: Tamper validation failed. {self.sha_path} not found.\n")
            self.db = set()
            return self.db
            
        try:
            with open(self.path, 'rb') as f:
                content = f.read()
            computed_sha = hashlib.sha256(content).hexdigest()
            
            with open(self.sha_path, 'r') as f:
                expected_sha = f.read().strip()
                
            if computed_sha != expected_sha:
                sys.stderr.write(f"CRITICAL WARNING: Tamper validation failed. SHA256 mismatch for {self.path}.\n")
                self.db = set()
                return self.db
                
            with open(self.path, "r") as f:
                self.db = set(json.load(f))
            return self.db
        except Exception as e:
            sys.stderr.write(f"CRITICAL WARNING: Error loading baseline: {e}\n")
            self.db = set()
            return self.db

    def save_baseline(self):
        try:
            content = json.dumps(list(self.db))
            computed_sha = hashlib.sha256(content.encode()).hexdigest()
            
            with open(self.path, "w") as f:
                f.write(content)
                
            with open(self.sha_path, "w") as f:
                f.write(computed_sha)
        except Exception as e:
            sys.stderr.write(f"Error saving baseline: {e}\n")

    def track_and_validate(self, fingerprint, sni, src_ip):
        if sni not in self.sni_origins:
            self.sni_origins[sni] = set()
        self.sni_origins[sni].add(src_ip)
        
        # Only allow commitment if 3+ distinct hosts contacted that SNI
        if len(self.sni_origins[sni]) >= 3:
            self.db.add(fingerprint)
            return True
        return False

    def is_known(self, fingerprint):
        return fingerprint in self.db
