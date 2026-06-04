# report.py - HTML Report Generator
import os
from datetime import datetime

REPORTS_DIR = "reports"

def generate_report(findings, output_file=None):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(REPORTS_DIR, f"report_{timestamp}.html")
    html = build_html(findings)
    with open(output_file, "w") as f:
        f.write(html)
    print(f"\n[+] Report saved to: {output_file}")
    return output_file

def build_html(findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    protocol_rows = ""
    for proto, count in findings["protocols"].items():
        protocol_rows += f"<tr><td>{proto}</td><td>{count}</td></tr>"

    suspicious_rows = ""
    if findings["suspicious_ports"]:
        for s in findings["suspicious_ports"]:
            suspicious_rows += f"<tr class='danger'><td>{s['src']}</td><td>{s['dst']}</td><td>{s['port']}</td><td>{s['service']}</td></tr>"
    else:
        suspicious_rows = "<tr><td colspan='4'>No suspicious ports detected</td></tr>"

    dns_rows = ""
    dns_list = list(set(findings["dns_queries"]))[:20]
    if dns_list:
        for q in dns_list:
            dns_rows += f"<tr><td>{q}</td></tr>"
    else:
        dns_rows = "<tr><td>No DNS queries captured</td></tr>"

    anomaly_rows = ""
    if findings["anomalies"]:
        for a in findings["anomalies"]:
            anomaly_rows += f"<tr class='danger'><td>⚠ {a}</td></tr>"
    else:
        anomaly_rows = "<tr><td>✅ No anomalies detected</td></tr>"

    portscan_rows = ""
    if findings["port_scan_suspects"]:
        for p in findings["port_scan_suspects"]:
            portscan_rows += f"<tr class='danger'><td>{p['ip']}</td><td>{p['ports_scanned']}</td><td>{', '.join(map(str, p['ports']))}</td></tr>"
    else:
        portscan_rows = "<tr><td colspan='3'>No port scans detected</td></tr>"

    html = (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "<title>Network Traffic Analysis Report</title>\n"
        "<style>\n"
        "body { font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }\n"
        "h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }\n"
        "h2 { color: #79c0ff; margin-top: 30px; }\n"
        ".meta { color: #8b949e; font-size: 14px; margin-bottom: 30px; }\n"
        ".stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }\n"
        ".stat-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; text-align: center; }\n"
        ".stat-box h3 { margin: 0; font-size: 28px; color: #58a6ff; }\n"
        ".stat-box p { margin: 5px 0 0; font-size: 12px; color: #8b949e; }\n"
        "table { width: 100%; border-collapse: collapse; margin-top: 10px; }\n"
        "th { background: #161b22; padding: 10px; text-align: left; border: 1px solid #30363d; color: #58a6ff; }\n"
        "td { padding: 8px 10px; border: 1px solid #30363d; font-size: 13px; }\n"
        "tr:hover { background: #161b22; }\n"
        "tr.danger td { color: #f85149; }\n"
        ".section { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }\n"
        ".footer { text-align: center; color: #8b949e; font-size: 12px; margin-top: 40px; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Network Traffic Analysis Report</h1>\n"
        f"<div class='meta'>Generated: {timestamp} &nbsp;|&nbsp; Total Packets Analyzed: <strong>{findings['total_packets']}</strong></div>\n"
        "<div class='stat-grid'>\n"
        f"<div class='stat-box'><h3>{findings['total_packets']}</h3><p>Total Packets</p></div>\n"
        f"<div class='stat-box'><h3>{len(findings['suspicious_ports'])}</h3><p>Suspicious Ports</p></div>\n"
        f"<div class='stat-box'><h3>{len(findings['anomalies'])}</h3><p>Anomalies</p></div>\n"
        f"<div class='stat-box'><h3>{len(findings['dns_queries'])}</h3><p>DNS Queries</p></div>\n"
        "</div>\n"
        "<div class='section'>\n"
        "<h2>Protocol Distribution</h2>\n"
        "<table><tr><th>Protocol</th><th>Packet Count</th></tr>\n"
        f"{protocol_rows}"
        "</table></div>\n"
        "<div class='section'>\n"
        "<h2>Anomalies Detected</h2>\n"
        "<table><tr><th>Description</th></tr>\n"
        f"{anomaly_rows}"
        "</table></div>\n"
        "<div class='section'>\n"
        "<h2>Suspicious Port Activity</h2>\n"
        "<table><tr><th>Source IP</th><th>Destination IP</th><th>Port</th><th>Service</th></tr>\n"
        f"{suspicious_rows}"
        "</table></div>\n"
        "<div class='section'>\n"
        "<h2>Port Scan Detection</h2>\n"
        "<table><tr><th>Suspect IP</th><th>Ports Scanned</th><th>Port List</th></tr>\n"
        f"{portscan_rows}"
        "</table></div>\n"
        "<div class='section'>\n"
        "<h2>DNS Queries</h2>\n"
        "<table><tr><th>Domain Queried</th></tr>\n"
        f"{dns_rows}"
        "</table></div>\n"
        "<div class='footer'>Network Traffic Analyzer — Labmentix Internship Project</div>\n"
        "</body>\n"
        "</html>"
    )

    return html