# analyzer.py - Protocol Analysis + Anomaly Detection
from scapy.all import IP, TCP, UDP, DNS, DNSQR, ARP
from collections import Counter, defaultdict

# Suspicious ports to flag
SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 25: "SMTP",
    445: "SMB", 3389: "RDP", 4444: "Metasploit",
    1337: "Hacker Port", 8080: "Alt HTTP",
    6667: "IRC", 31337: "Elite/Backdoor"
}

# Port scan detection threshold
PORT_SCAN_THRESHOLD = 10

def analyze_packets(packets):
    """
    Main analysis function - returns a findings dictionary
    """
    print("\n[*] Analyzing packets...\n")

    findings = {
        "total_packets": len(packets),
        "protocols": Counter(),
        "ip_traffic": Counter(),
        "suspicious_ports": [],
        "dns_queries": [],
        "arp_activity": [],
        "port_scan_suspects": [],
        "anomalies": []
    }

    # Track ports per IP for port scan detection
    ip_ports = defaultdict(set)

    for packet in packets:

        # ---- Protocol Detection ----
        if packet.haslayer(IP):
            findings["protocols"]["IP"] += 1
            src = packet[IP].src
            dst = packet[IP].dst
            findings["ip_traffic"][src] += 1

            # TCP Analysis
            if packet.haslayer(TCP):
                findings["protocols"]["TCP"] += 1
                dport = packet[TCP].dport
                sport = packet[TCP].sport
                ip_ports[src].add(dport)

                # Check suspicious ports
                if dport in SUSPICIOUS_PORTS:
                    findings["suspicious_ports"].append({
                        "src": src,
                        "dst": dst,
                        "port": dport,
                        "service": SUSPICIOUS_PORTS[dport]
                    })

            # UDP Analysis
            if packet.haslayer(UDP):
                findings["protocols"]["UDP"] += 1
                dport = packet[UDP].dport
                ip_ports[src].add(dport)

        # ---- DNS Query Extraction ----
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode(errors="ignore")
            findings["dns_queries"].append(query)
            findings["protocols"]["DNS"] += 1

        # ---- ARP Activity ----
        if packet.haslayer(ARP):
            findings["protocols"]["ARP"] += 1
            findings["arp_activity"].append({
                "src": packet[ARP].psrc,
                "dst": packet[ARP].pdst,
                "op": "request" if packet[ARP].op == 1 else "reply"
            })

    # ---- Port Scan Detection ----
    for ip, ports in ip_ports.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            findings["port_scan_suspects"].append({
                "ip": ip,
                "ports_scanned": len(ports),
                "ports": list(ports)[:20]  # show first 20
            })
            findings["anomalies"].append(
                f"Possible port scan from {ip} — {len(ports)} ports targeted"
            )

    # ---- Top Talkers Anomaly ----
    if findings["ip_traffic"]:
        top_ip, top_count = findings["ip_traffic"].most_common(1)[0]
        if top_count > 50:
            findings["anomalies"].append(
                f"High traffic volume from {top_ip} — {top_count} packets"
            )

    print(f"[+] Analysis complete — {len(findings['anomalies'])} anomalies found")
    return findings

def print_summary(findings):
    """
    Print a quick summary to terminal
    """
    print("\n" + "="*50)
    print("         TRAFFIC ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total Packets     : {findings['total_packets']}")
    print(f"Protocols Seen    : {dict(findings['protocols'])}")
    print(f"Suspicious Ports  : {len(findings['suspicious_ports'])}")
    print(f"DNS Queries       : {len(findings['dns_queries'])}")
    print(f"ARP Events        : {len(findings['arp_activity'])}")
    print(f"Port Scan Suspects: {len(findings['port_scan_suspects'])}")
    print(f"Anomalies Found   : {len(findings['anomalies'])}")

    if findings["anomalies"]:
        print("\n[!] ANOMALIES DETECTED:")
        for a in findings["anomalies"]:
            print(f"  ⚠  {a}")
    print("="*50)