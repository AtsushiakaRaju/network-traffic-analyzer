# capture.py - Packet Capture Module
from scapy.all import sniff, wrpcap, rdpcap
import os

SAMPLES_DIR = "samples"
DEFAULT_PCAP = os.path.join(SAMPLES_DIR, "capture.pcap")

def capture_live(interface="eth0", packet_count=100, output_file=DEFAULT_PCAP):
    """
    Capture live packets from a network interface
    """
    print(f"\n[*] Starting live capture on interface: {interface}")
    print(f"[*] Capturing {packet_count} packets...")
    print("[*] Press Ctrl+C to stop early\n")

    try:
        packets = sniff(iface=interface, count=packet_count)
        wrpcap(output_file, packets)
        print(f"\n[+] Captured {len(packets)} packets")
        print(f"[+] Saved to: {output_file}")
        return packets

    except PermissionError:
        print("[-] Permission denied. Run as root!")
        return None
    except Exception as e:
        print(f"[-] Error during capture: {e}")
        return None

def load_pcap(filepath=DEFAULT_PCAP):
    """
    Load packets from an existing .pcap file
    """
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return None

    print(f"\n[*] Loading packets from: {filepath}")
    packets = rdpcap(filepath)
    print(f"[+] Loaded {len(packets)} packets")
    return packets

def get_interfaces():
    """
    List available network interfaces
    """
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print("\n[*] Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    return interfaces