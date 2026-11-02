# Sample Zeek Logs (Synthetic Data)

These synthetic logs (`conn.log`, `dns.log`, and `ssl.log`) were generated to test the analytical detection capabilities of the Zeek-C2-Detection pipeline. They contain a mix of benign traffic and heavily simulated malware behavior.

## 192.168.1.11 (Beaconing + Idle C2)
This internal host simulates a periodic malware beacon. In the `dns.log`, it consistently queries `evil-c2.com` exactly every 60 seconds (with minimal jitter), resulting in an extremely low Coefficient of Variation (CV). Simultaneously, in the `conn.log` and `ssl.log`, it establishes a long-running TLS session to the C2 server (`198.51.100.1`) that lasts over an hour while transferring fewer than 1,000 bytes, representing an open but idle reverse shell.

## 192.168.1.12 (DNS Tunneling + Exfiltration)
This host demonstrates data theft techniques. In the `dns.log`, it attempts DNS tunneling by requesting unusually long subdomains (e.g., `zxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm.tunnel.com`) with a `TXT` record type, triggering high Shannon entropy alerts. Concurrently in the `conn.log`, it opens a session where it uploads over 5MB of data while downloading only 1KB, heavily skewing the data asymmetry ratios and flagging our Exfiltration detection.

## 192.168.1.13 (Fast-Flux + Strobe)
This host exhibits erratic connection behavior typical of a compromised machine scanning or participating in a botnet. In the `dns.log`, it queries `fastflux.com` which resolves to multiple varying IP addresses with a Time-To-Live (TTL) of just 60 seconds, triggering the Fast-Flux detection. In the `conn.log`, it aggressively connects to `198.51.100.3` more than 100 times within a short time window, triggering a Strobe/Connection Flood alert.
