import os
from datetime import datetime
from typing import List

def generate_html_report(profiles: List, output_path: str = "output/report.html"):
    """
    Generates a single-file self-contained HTML SOC dashboard report.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    total_hosts = len(profiles)
    total_alerts = sum(len(p.top_reasons) for p in profiles)
    highest_score = round(profiles[0].unified_score, 1) if profiles else 0.0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zeek-C2-Detection SOC Dashboard</title>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --border: #334155;
        }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-bar {{
            display: flex;
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 8px;
            flex: 1;
            text-align: center;
            border: 1px solid var(--border);
        }}
        .summary-value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent);
            margin-top: 0.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #0f172a;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.05em;
        }}
        .progress-bg {{
            background: var(--border);
            height: 8px;
            border-radius: 4px;
            width: 100%;
            overflow: hidden;
            margin-top: 5px;
        }}
        .progress-fill {{
            height: 100%;
            border-radius: 4px;
        }}
        .badge {{
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            margin-right: 4px;
            background: #334155;
            display: inline-block;
        }}
        .badge.beacon {{ color: #a78bfa; }}
        .badge.dns {{ color: #38bdf8; }}
        .badge.long_conn {{ color: #fbbf24; }}
        .badge.strobe {{ color: #f87171; }}
        .badge.threat_intel {{ color: #fb923c; }}
        .badge.ja3 {{ color: #a3e635; }}
        
        .expandable-row {{ cursor: pointer; }}
        .expandable-row:hover {{ background: #283548; }}
        .details-row {{
            display: none;
            background: #0f172a;
        }}
        .details-content {{ padding: 1rem 2rem; }}
        
        .bar-chart-container {{
            background: var(--bg-card);
            padding: 2rem;
            border-radius: 8px;
            margin-top: 2rem;
            border: 1px solid var(--border);
        }}
        .bar-row {{
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }}
        .bar-label {{ width: 120px; font-weight: bold; color: var(--text-muted); }}
        .bar-wrap {{ flex: 1; background: var(--border); height: 20px; border-radius: 4px; overflow: hidden; }}
        .bar-val {{ height: 100%; background: var(--accent); display: flex; align-items: center; padding-left: 10px; font-size: 0.8rem; color: #fff; }}
        
        .footer {{
            margin-top: 3rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Zeek-C2-Detection <span style="color: var(--accent)">Dashboard</span></h1>
        <div style="color: var(--text-muted)">{timestamp}</div>
    </div>

    <div class="summary-bar">
        <div class="summary-card">
            <div>TOTAL HOSTS ANALYZED</div>
            <div class="summary-value">{total_hosts}</div>
        </div>
        <div class="summary-card">
            <div>TOTAL ALERTS</div>
            <div class="summary-value">{total_alerts}</div>
        </div>
        <div class="summary-card">
            <div>HIGHEST RISK SCORE</div>
            <div class="summary-value" style="color: {'var(--red)' if highest_score > 70 else 'var(--orange)' if highest_score > 40 else 'var(--yellow)'}">{highest_score}</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Rank</th>
                <th>IP Address</th>
                <th style="width: 20%">Risk Score</th>
                <th>Triggered Modules</th>
                <th>Top Reason</th>
            </tr>
        </thead>
        <tbody>
"""

    for idx, p in enumerate(profiles):
        score = p.unified_score
        color = "var(--red)" if score > 70 else "var(--orange)" if score > 40 else "var(--yellow)"
        
        badges = []
        if p.beacon_score > 0: badges.append('<span class="badge beacon">BEACON</span>')
        if p.dns_score > 0: badges.append('<span class="badge dns">DNS</span>')
        if p.long_conn_score > 0: badges.append('<span class="badge long_conn">LONG CONN</span>')
        if p.strobe_score > 0: badges.append('<span class="badge strobe">STROBE</span>')
        if p.threat_intel_score > 0: badges.append('<span class="badge threat_intel">INTEL</span>')
        if p.ja3_score > 0: badges.append('<span class="badge ja3">JA3</span>')
        
        top_reason = p.top_reasons[0] if p.top_reasons else "N/A"
        
        html += f"""
            <tr class="expandable-row" onclick="toggleDetails('details-{idx}')">
                <td>#{idx+1}</td>
                <td style="font-weight: bold; font-family: monospace;">{p.src_ip}</td>
                <td>
                    <div style="font-weight: bold; color: {color}">{score:.1f} / 100</div>
                    <div class="progress-bg">
                        <div class="progress-fill" style="width: {min(100, score)}%; background: {color}"></div>
                    </div>
                </td>
                <td>{' '.join(badges)}</td>
                <td style="color: var(--text-muted); font-size: 0.9rem;">{top_reason}</td>
            </tr>
            <tr id="details-{idx}" class="details-row">
                <td colspan="5">
                    <div class="details-content">
                        <h4 style="margin-top:0">Module Breakdown</h4>
                        <ul style="color: var(--text-muted); font-size: 0.9rem;">
                            <li>Beacon Score: {p.beacon_score:.1f}</li>
                            <li>DNS Score: {p.dns_score:.1f}</li>
                            <li>Long Conn Score: {p.long_conn_score:.1f}</li>
                            <li>Strobe Score: {p.strobe_score:.1f}</li>
                            <li>Threat Intel Score: {p.threat_intel_score:.1f}</li>
                            <li>JA3 Score: {p.ja3_score:.1f}</li>
                        </ul>
                        <h4>All Reasons</h4>
                        <ul style="color: var(--text-muted); font-size: 0.9rem;">
                            {''.join(f'<li>{r}</li>' for r in p.top_reasons)}
                        </ul>
                    </div>
                </td>
            </tr>
"""

    html += """
        </tbody>
    </table>
"""

    if profiles:
        top = profiles[0]
        html += f"""
    <div class="bar-chart-container">
        <h3>Top Threat Distribution ({top.src_ip})</h3>
        <div style="margin-top: 1.5rem;">
"""
        for mod, val in top.module_breakdown.items():
            if val > 0:
                html += f"""
            <div class="bar-row">
                <div class="bar-label">{mod.replace('_', ' ').upper()}</div>
                <div class="bar-wrap">
                    <div class="bar-val" style="width: {val}%">{val:.1f}</div>
                </div>
            </div>
"""
        html += """
        </div>
    </div>
"""

    html += f"""
    <div class="footer">
        Generated by Zeek-C2-Detection &bull; {timestamp}
    </div>

    <script>
        function toggleDetails(id) {{
            var el = document.getElementById(id);
            if (el.style.display === "table-row") {{
                el.style.display = "none";
            }} else {{
                el.style.display = "table-row";
            }}
        }}
    </script>
</body>
</html>
"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"\n[+] SOC Dashboard Report generated at: {output_path}")
