# Zeek-C2-Detection

A Python-based, RITA-inspired Command and Control (C2) detection engine built directly on top of Zeek logs (`ssl.log`, `conn.log`, `dns.log`). It uses rolling statistical windows, behavioral math, and integrated intelligence to detect beaconing malware, fast-flux networks, data exfiltration, and more.

## Architecture

Unlike RITA, which heavily depends on Bro logs ingested into MongoDB, this project parses Zeek TSV logs directly (via `pandas` and custom fast parsers) and performs in-memory rolling statistical analysis. It heavily penalizes SSL-encrypted anomalies, uses monotonic clocks to resist NTP manipulation, and uses multi-host validation to prevent baseline poisoning.

## Modules

The detection engine combines 6 primary modules, weighted and scored holistically:

1. **DNS Analysis (`modules/dns_analyzer.py`) - 20% Weight**
   - **Beaconing**: Calculates Coefficient of Variation (CV) on DNS query intervals.
   - **Tunneling**: Flags high Shannon entropy (>3.5 bits) and long TXT/NULL queries.
   - **Fast-Flux**: Detects TTLs < 300s resolving to 3+ different IPs.
   - **DGA Detection**: Flags anomalous consonant-to-vowel ratios.

2. **Long Connections (`modules/long_conn.py`) - 15% Weight**
   - **Idle C2 channels**: Duration > 300s but low data transfer.
   - **Exfiltration**: Asymmetric uploads (orig_bytes > resp_bytes * 10).
   - **Persistence**: Low-and-slow tracking (>50 short connections over an hour).

3. **Strobe Detection (`modules/strobe_detector.py`) - 10% Weight**
   - Detects connection floods (>100 conns/hr) and port scanning to single IPs.
   - **CDN Suppression**: Automatically downgrades severity if the destination belongs to known CDNs (Cloudflare, AWS, Azure).

4. **Threat Intelligence (`modules/threat_intel.py`) - 15% Weight**
   - Cross-references domains/IPs against local blocklists or Abuse.ch feeds.
   - **Multi-Host Amplification**: Automatically amplifies the score (1.5x) if 3+ internal hosts contact the same blacklisted IP.

5. **SSL/JA3 Beaconing (`behavioral_analyzer.py`) - 35% Weight**
   - Calculates CV, Autocorrelation, and Spectral Dominance (FFT) on SSL flows.
   - **JA3 Rarity (`ja3_intelligence.py`) - 5% Weight**: Profiles internal JA3 frequencies.

6. **Unified Scorer (`modules/unified_scorer.py`)**
   - Consolidates all alerts into a `HostRiskProfile`.
   - Ranks all `src_ip`s from 0-100 based on the weights above.

## Usage

Use the `main.py` entry point to analyze logs either batch or live.

### Basic Batch Analysis
```bash
python main.py --ssl logs/ssl.log --conn logs/conn.log --dns logs/dns.log --threat-intel-file feeds/abuse.csv
```

### Output to JSON (for SIEM Integration)
```bash
python main.py --ssl logs/ssl.log --conn logs/conn.log --output json
```

### Live Tail Mode (Streaming)
```bash
python main.py --ssl /opt/zeek/logs/current/ssl.log --live --window 60
```

### Command Line Arguments
* `--ssl`: Path to Zeek ssl.log (Required)
* `--conn`: Path to Zeek conn.log
* `--dns`: Path to Zeek dns.log
* `--threat-intel-file`: Path to CSV or TXT threat feed
* `--output`: Output format (`console`, `json`, `csv`)
* `--min-score`: Minimum unified score to alert on (default: 20.0)
* `--live`: Tail the files continuously instead of exiting at EOF.
* `--baseline`: Run in learning mode to establish a known-good baseline.
* `--baseline-freeze`: Compare against baseline without adding new entries.

## Detection Results
Running the pipeline against our provided `data/sample_logs/` correctly prioritizes the synthetic C2 behaviors:

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

## Test Coverage
The project includes a full unit test suite covering clean traffic, true positive C2 behavior, and critical edge cases across all modules.

```text
$ python -m unittest discover -s tests
...............
----------------------------------------------------------------------
Ran 15 tests in 0.150s

OK
```

## Datasets

`data/sample_logs/` contains small Zeek logs for a quick run:

```bash
python main.py --ssl data/sample_logs/ssl.log --conn data/sample_logs/conn.log \
  --dns data/sample_logs/dns.log --threat-intel-file feeds/abuse_ch.csv
```

The full evaluation used the public **CTU-13** botnet captures (scenarios 42–45),
converted to Zeek logs under `data/real_logs/`. Those files are about 2 GB, so they
are not included in this repository. Download CTU-13 from the Stratosphere Lab and
place the Zeek logs in `data/real_logs/CTU13-Botnet4X/` to reproduce the results.
