# main.py - Entry Point
import os
from capture import capture_live, load_pcap, get_interfaces
from analyzer import analyze_packets, print_summary
from report import generate_report

def main():
    print("""
╔══════════════════════════════════════╗
║     NETWORK TRAFFIC ANALYZER        ║
║     Labmentix Internship Project     ║
╚══════════════════════════════════════╝
    """)

    print("Select Mode:")
    print("  [1] Live Capture")
    print("  [2] Analyze existing .pcap file")
    choice = input("\nEnter choice (1 or 2): ").strip()

    packets = None

    if choice == "1":
        interfaces = get_interfaces()
        iface_input = input("\nEnter interface name (e.g. eth0): ").strip()
        count = input("How many packets to capture? (default 100): ").strip()
        count = int(count) if count.isdigit() else 100
        packets = capture_live(interface=iface_input, packet_count=count)

    elif choice == "2":
        path = input("\nEnter path to .pcap file (default: samples/capture.pcap): ").strip()
        if not path:
            path = "samples/capture.pcap"
        packets = load_pcap(path)

    else:
        print("[-] Invalid choice. Exiting.")
        return

    if packets is None:
        print("[-] No packets to analyze. Exiting.")
        return

    # Analyze
    findings = analyze_packets(packets)

    # Print summary to terminal
    print_summary(findings)

    # Generate HTML report
    generate_report(findings)