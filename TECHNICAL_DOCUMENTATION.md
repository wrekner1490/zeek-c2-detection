# Zeek-C2-Detection Technical Documentation

## Project Overview
Zeek-C2-Detection is a comprehensive Command and Control (C2) detection engine written in Python. It ingests Zeek network logs (`conn.log`, `dns.log`, `ssl.log`) and applies statistical, behavioral, and intelligence-based heuristics to detect compromised hosts. 

While heavily inspired by the RITA (Real Intelligence Threat Analytics) framework, this system differs by functioning entirely in-memory using `pandas` dataframes instead of relying on an external MongoDB backend. Furthermore, it incorporates advanced techniques not present in RITA, such as specific penalization for SSL/TLS encrypted anomalies, native fast-flux detection, and multi-host threat intelligence amplification.

---

## System Architecture

The pipeline processes Zeek TSV logs in phases, starting from raw log ingestion through to unified alerting.

```text
[ Zeek Logs (conn, dns, ssl) ]
           |
           v
+-------------------------------+
|     Data Ingestion Layer      | 
| (zeek_parser, conn_log_reader)|
+-------------------------------+
           |
           v
+-------------------------------+
|    Behavioral Profiling       |
| (ja3_extractor, ja3_intel,    |
|  behavioral_analyzer)         |
+-------------------------------+
           |
           v
+-------------------------------------------------------------+
|               Analytical Detection Modules                  |
|                                                             |
|  [DNS Analyzer]  [Long Conn]  [Strobe]  [Threat Intel]      |
+-------------------------------------------------------------+
           |
           v
+-------------------------------+
|    Multi-Host Baseline DB     | <-- Validates if behavior is
|    (baseline_validator)       |     historically normal
+-------------------------------+
           |
           v
+-------------------------------+
|     Unified Scoring Engine    | <-- Weights and combines scores 
|      (unified_scorer)         |     (0-100) per source IP
+-------------------------------+
           |
           v
[ JSON/Console Alerts (zeek_c2_hunter_live) ]
```

---

## Core Existing Modules

These modules represent the foundational pipeline for parsing SSL records, computing basic periodicity, and ensuring baseline validation.

### `zeek_parser.py`
- **Purpose**: Minimal parser for Phase 1 Zeek TSV logs.
- **Key Classes/Functions**: Standard functions to extract `ts`, `id.orig_h`, `id.resp_h`, `server_name`, and `ja3`.
- **Inputs**: Raw `ssl.log` lines.
- **Outputs**: Dictionary mappings of rows.
- **Pipeline Role**: The foundational parser that feeds the extractor.

### `ja3_extractor.py`
- **Purpose**: Phase 2 log extraction with rotation handling.
- **Key Classes/Functions**: `ZeekSSLRecord`, `process_ja3_data()`
- **Inputs**: `ssl.log` file path.
- **Outputs**: Yields `ZeekSSLRecord` objects.
- **Pipeline Role**: Ingests the SSL log data into memory securely, even in streaming/tail mode.

### `ja3_intelligence.py`
- **Purpose**: Tracks global JA3 frequency and computes rarity.
- **Key Classes/Functions**: `FlowData`, `JA3Intelligence`
- **Inputs**: `ZeekSSLRecord` objects.
- **Outputs**: Updated global frequency maps and grouped `FlowData` instances.
- **Pipeline Role**: Builds the groundwork for behavioral analysis by grouping packets by flow (`src->dst:port (SNI)`).

### `behavioral_analyzer.py`
- **Purpose**: Computes mathematical periodicity (beaconing).
- **Key Classes/Functions**: `FlowBehavior` (computes variance, std_dev, CV, Autocorrelation, Spectral Dominance).
- **Inputs**: `FlowData` from the intelligence layer.
- **Outputs**: `FlowBehavior` instances mapped to scores.
- **Pipeline Role**: Identifies highly periodic traffic disguised by jitter.

### `correlation_engine.py`
- **Purpose**: Correlates behavioral statistics with basic metrics.
- **Key Classes/Functions**: `CorrelationEngine`
- **Inputs**: `FlowBehavior`, `conn_reader`
- **Outputs**: `RiskLevel`, `label`, `reasons`
- **Pipeline Role**: Issues the initial SSL beaconing scores.

### `conn_log_reader.py`
- **Purpose**: Asynchronous reader for `conn.log` to fetch byte counts.
- **Key Classes/Functions**: `ConnLogReader` (LRU cache for uids).
- **Inputs**: `conn.log` file path.
- **Outputs**: Byte count dictionaries mapped by `uid`.
- **Pipeline Role**: Allows the correlation engine to check for encryption blindness.

### `baseline_validator.py`
- **Purpose**: Tracks historically known SNI->IP mappings.
- **Key Classes/Functions**: `BaselineValidator`
- **Inputs**: Fingerprints.
- **Outputs**: True/False if the behavior is known.
- **Pipeline Role**: Prevents alerting on normally occurring, periodic benign software (e.g., update checkers).

### `flow_state_manager.py`
- **Purpose**: Persists flow state across restarts.
- **Key Classes/Functions**: `FlowStateManager`
- **Inputs**: Flow dictionaries.
- **Outputs**: Pickled SQLite states.
- **Pipeline Role**: Ensures long-running streams don't lose context on reboot.

### `flow_timer.py`
- **Purpose**: Wraps `time.monotonic()` to prevent NTP evasion.
- **Key Classes/Functions**: `FlowTimer`
- **Inputs**: None.
- **Outputs**: Monotonic floats.
- **Pipeline Role**: Used globally to calculate true intervals.

### `zeek_c2_hunter.py` & `zeek_c2_hunter_live.py`
- **Purpose**: The core orchestration engines for batch and live running respectively.
- **Key Classes/Functions**: `live_monitor()`, `_evaluate_active_flows()`
- **Inputs**: User CLI arguments and parsed data.
- **Outputs**: Final JSON or Console alerts.
- **Pipeline Role**: Wires all modules together, manages the garbage collection loop, and outputs the final data.

### `config.yaml`
- **Purpose**: Stores configurations like thresholds and mock ASN/Geo DBs.
- **Pipeline Role**: Central config reference.

---

## New RITA-Inspired Modules

### 1. `dns_analyzer.py`
- **Purpose**: Detects DNS Beaconing, Tunneling, Fast-Flux networks, and Domain Generation Algorithms (DGA).
- **Detection Algorithm**:
  - **Beaconing**: Calculates the Coefficient of Variation (Standard Deviation / Mean) of query intervals. CV < 0.5 flags a beacon.
  - **Tunneling**: Calculates Shannon Entropy of the query string. Entropy > 3.5 or length > 52 with TXT/NULL records flags a tunnel.
  - **Fast-Flux**: Checks if minimum TTL is < 300s and > 3 unique IPs are returned.
  - **DGA**: Flags if the Consonant/Vowel ratio exceeds 4.0.
- **Key Classes/Methods**: `DNSAnalyzer.analyze()`, `DNSAlert`
- **Inputs/Outputs**: Takes a `dns.log` path/DataFrame; returns a list of `DNSAlert` dataclasses.
- **Scoring Logic**: 0-100 base. 
- **Unique Twist**: SSL Cross-referencing. If a domain is queried but never appears in any SSL SNI, a +15 score penalty is applied.
- **Example Alert Evidence**:
  ```json
  {"cv": 0.0017, "mean_interval": 60.0, "count": 4, "ssl_sni_missing": true}
  ```

### 2. `long_conn.py`
- **Purpose**: Detects persistent low-and-slow connections, idle C2 channels, and data exfiltration.
- **Detection Algorithm**:
  - **Long Conn**: Duration > 300s.
  - **Idle C2**: Duration > 300s AND total bytes transferred < 10,000.
  - **Exfiltration**: Uploaded bytes > (Downloaded bytes * 10) AND Upload > 1MB.
  - **Low and Slow**: > 50 connections to the same IP with a mean duration > 60s.
- **Key Classes/Methods**: `LongConnectionAnalyzer.analyze()`, `LongConnAlert`
- **Inputs/Outputs**: Takes `conn.log` path/DataFrame; returns `LongConnAlert` objects.
- **Scoring Logic**: Base 60-80 depending on the type.
- **Unique Twist**: JA3 Correlation. If the connection's `uid` maps to a known SSL beacon, the score is multiplied by 1.5.
- **Example Alert Evidence**:
  ```json
  {"duration": 3600.0, "total_bytes": 700, "is_beacon": true}
  ```

### 3. `strobe_detector.py`
- **Purpose**: Identifies connection floods and aggressive port scanning.
- **Detection Algorithm**:
  - Groups connections by `src_ip` and `dst_ip`.
  - **Flood**: Flags if total connections > 100 within the batch window.
  - **Port Scan**: Flags if unique ports > 20 within the batch window.
- **Key Classes/Methods**: `StrobeDetector.analyze()`, `StrobeAlert`
- **Inputs/Outputs**: Takes `conn.log`; returns `StrobeAlert` objects.
- **Scoring Logic**: Base 75-80. 
- **Unique Twist**: CDN Suppression. Automatically references a mock ASN database to drastically downgrade scores (to 25-30) if the destination IP is a known CDN (e.g., Cloudflare/AWS), effectively squashing standard RITA false positives.
- **Example Alert Evidence**:
  ```json
  {"total_conns": 120, "unique_ports": 1, "cdn": false}
  ```

### 4. `threat_intel.py`
- **Purpose**: Matches connections against known bad infrastructure.
- **Detection Algorithm**:
  - Loads Abuse.ch or standard TXT files.
  - Exact IP hits score 100. Domain hits score 80. /24 Subnets score 60.
- **Key Classes/Methods**: `ThreatIntelChecker.analyze_contact()`, `ThreatIntelAlert`
- **Inputs/Outputs**: Takes `src_ip`, `dst_ip`, and `domain`; returns a single `ThreatIntelAlert` (or None).
- **Scoring Logic**: 40-100 base score.
- **Unique Twist**: Multi-Host Amplification. If 3 or more internal hosts contact the exact same indicator, the base score is amplified by 1.5x (capped at 100).
- **Example Alert Evidence**:
  ```json
  {"hosts_contacted": 3, "amplified": true}
  ```

---

## Unified Scoring Engine
The `UnifiedScorer` class consumes alerts from all detection modules and calculates a final, holistic risk score for every internal `src_ip` on the network.

**Weighting System**:
- SSL Beaconing: **35%**
- DNS Anomalies: **20%**
- Long Connections: **15%**
- Threat Intelligence: **15%**
- Strobe Behavior: **10%**
- JA3 Frequency Rarity: **5%**

**How it works**:
As alerts fire, the Scorer tracks the highest severity score per module for each host. During `compute_all_scores()`, it calculates the weighted sum of these high-water marks. The output is a sorted list of `HostRiskProfile` objects ranked from 100 down to 0, ensuring Security Analysts focus on the most multifaceted threats first.

---

## Unit Test Suite
The project utilizes Python's built-in `unittest` framework, validating data with pandas.

1. `test_dns_analyzer.py`
   - **`test_clean_traffic`**: Passes normal google.com query. Expected: 0 alerts.
   - **`test_dns_tunneling_true_positive`**: Passes high entropy long TXT record. Expected: TUNNEL alert.
   - **`test_edge_case_empty_dataframe`**: Passes broken/empty DataFrame. Expected: 0 alerts / No crash.
2. `test_long_conn.py`
   - **`test_clean_traffic`**: Short 10s connection. Expected: 0 alerts.
   - **`test_exfiltration_true_positive`**: 5MB upload, 1KB download. Expected: EXFILTRATION alert.
   - **`test_edge_case_missing_bytes`**: Passing NaN/None values. Expected: IDLE_C2 fallback alert.
3. `test_strobe_detector.py`
   - **`test_clean_traffic`**: 5 connections. Expected: 0 alerts.
   - **`test_strobe_true_positive`**: 105 connections to non-CDN IP. Expected: CONNECTION_FLOOD alert, `asn_suppressed`=False.
   - **`test_edge_case_cdn_suppression`**: 105 connections to Cloudflare IP. Expected: CONNECTION_FLOOD alert with low score, `asn_suppressed`=True.
4. `test_threat_intel.py`
   - **`test_clean_traffic`**: Normal 8.8.8.8 check. Expected: None.
   - **`test_true_positive_ip`**: Check against loaded bad IP. Expected: EXACT_IP match.
   - **`test_edge_case_amplification`**: Hit bad IP from 3 distinct internal IPs sequentially. Expected: 3rd hit has `amplified=True` and higher score.
5. `test_unified_scorer.py`
   - **`test_clean_traffic`**: Empty inputs. Expected: Score 0.
   - **`test_true_positive_accumulation`**: Feeds Beacon(100) and DNS(100). Expected: Final score of 55.0.
   - **`test_edge_case_highest_score_wins`**: Feeds Strobe(50) and Strobe(90). Expected: Final Strobe score used is 90.

**Test Output**:
```text
$ python -m unittest discover -s tests
...............
----------------------------------------------------------------------
Ran 15 tests in 0.150s

OK
```

---

## How to Run

### Running with Sample Logs
To execute the pipeline against local TSV logs:
```bash
python main.py --ssl data/sample_logs/ssl.log \
               --conn data/sample_logs/conn.log \
               --dns data/sample_logs/dns.log \
               --threat-intel-file feeds/abuse_ch.csv \
               --min-score 20.0
```

### Running with Docker
1. Build the image:
```bash
docker build -t zeek-c2 .
```
2. Run the image:
```bash
docker run zeek-c2
```

### Running Unit Tests
```bash
python -m unittest discover -s tests
```

### Running Live Tail Mode
To tail active Zeek logs dynamically (e.g. in a `/opt/zeek/logs/` directory):
```bash
python main.py --ssl ssl.log --conn conn.log --dns dns.log --live --window 60
```

---

## Sample Detection Output
```text
[*] Starting Zeek-C2-Detection Main Pipeline...
[*] Loading Threat Intel from feeds/abuse_ch.csv...
[+] Loaded 1 IPs and 2 domains.
[*] Starting C2 Live Monitor with Unified Scoring (Phase 8)
    - SSL Log: data/sample_logs/ssl.log
    - DNS Log: data/sample_logs/dns.log
    - Conn Log: data/sample_logs/conn.log
    - Tailing: False
    - Restored flows: 0

[!] Unified Host Risk Rankings:
    - IP: 192.168.1.12 | Risk Score: 32.0/100
        * [LONG_CONN] LONG_CONN to 198.51.100.2
        * [DNS] TUNNEL: zxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm.tunnel.com
        * [LONG_CONN] EXFILTRATION to 198.51.100.2
    - IP: 192.168.1.11 | Risk Score: 30.2/100
        * [LONG_CONN] IDLE_C2 to 198.51.100.1
        * [DNS] BEACON: evil-c2.com
    - IP: 192.168.1.13 | Risk Score: 25.5/100
        * [DNS] FASTFLUX: fastflux.com
        * [STROBE] CONNECTION_FLOOD to 198.51.100.3
```

---

## Project File Structure

```text
Zeek-C2-Detection/
├── baseline.json               # Persisted baseline knowledge database
├── baseline_validator.py       # Anti-poisoning baseline checks
├── behavioral_analyzer.py      # Core math engine for periodicity (CV/FFT)
├── config.yaml                 # Static configurations and thresholds
├── conn_log_reader.py          # LRU cached byte lookup for conn.log
├── correlation_engine.py       # Base correlation for SSL anomalies
├── data/
│   └── sample_logs/
│       ├── conn.log            # Synthetic connection logs
│       ├── dns.log             # Synthetic DNS logs
│       ├── README.md           # Documentation for sample IPs
│       └── ssl.log             # Synthetic SSL logs
├── Dockerfile                  # Containerization instructions
├── feeds/
│   └── abuse_ch.csv            # Mock Abuse.ch threat intel feed
├── flow_state_manager.py       # SQLite persistence for rolling state
├── flow_timer.py               # Monotonic time wrapper
├── ja3_extractor.py            # Log parsing and inode-aware tailing
├── ja3_intelligence.py         # Global JA3 frequency profiling
├── main.py                     # Entry point for the application
├── modules/
│   ├── dns_analyzer.py         # RITA: DNS tunneling, FF, DGA, Beaconing
│   ├── long_conn.py            # RITA: Long connections and Exfiltration
│   ├── strobe_detector.py      # RITA: Strobe and port scan detection
│   ├── threat_intel.py         # RITA: Threat intelligence matching
│   └── unified_scorer.py       # Combines all module scores (0-100)
├── README.md                   # Main project documentation
├── requirements.txt            # Python dependencies
├── scratch_gen.py              # Script to generate synthetic logs
├── tests/
│   ├── test_dns_analyzer.py    # Unit tests for DNS Analyzer
│   ├── test_long_conn.py       # Unit tests for Long Connection logic
│   ├── test_strobe_detector.py # Unit tests for Strobe Detection
│   ├── test_threat_intel.py    # Unit tests for Threat Intel caching
│   └── test_unified_scorer.py  # Unit tests for mathematical weighting
├── zeek_c2_hunter.py           # Legacy batch-mode runner
├── zeek_c2_hunter_live.py      # Integrated live stream engine
└── zeek_parser.py              # Legacy raw log dictionary parser
```
