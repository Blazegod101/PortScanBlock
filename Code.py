from scapy.all import sniff, TCP
from collections import defaultdict
import time
import subprocess

# Threshold settings
PORT_SCAN_THRESHOLD = 10  # Number of ports scanned to trigger a block
TIME_WINDOW = 10  # Time window in seconds to detect port scanning

# Data structures to track port scanning
ip_scan_activity = defaultdict(list)  # Tracks IPs and the ports they're scanning
blocked_ips = set()  # Keep track of already blocked IPs

def block_ip(ip_address):
    """
    Block the given IP address using iptables.
    """
    if ip_address not in blocked_ips:
        print(f"[!] Blocking IP: {ip_address}")
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            blocked_ips.add(ip_address)
            print(f"[+] Successfully blocked IP: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to block IP: {ip_address}. Error: {e}")
    else:
        print(f"[!] IP {ip_address} is already blocked.")

def detect_port_scan(packet):
    """
    Detect port scanning activity by monitoring incoming TCP SYN packets.
    """
    if packet.haslayer(TCP) and packet[TCP].flags == "S":  # Check for SYN packets
        source_ip = packet[0].src
        dest_port = packet[TCP].dport
        current_time = time.time()

        # Log the port access for the source IP
        ip_scan_activity[source_ip].append((dest_port, current_time))

        # Clean up old records for the IP (outside of TIME_WINDOW)
        ip_scan_activity[source_ip] = [
            (port, timestamp) for port, timestamp in ip_scan_activity[source_ip]
            if current_time - timestamp <= TIME_WINDOW
        ]

        # Check if the IP has scanned too many ports within the time window
        scanned_ports = {entry[0] for entry in ip_scan_activity[source_ip]}  # Unique ports
        if len(scanned_ports) > PORT_SCAN_THRESHOLD:
            print(f"[!] Detected port scan from {source_ip}. Scanned {len(scanned_ports)} ports.")
            block_ip(source_ip)

def main():
    print("Starting port scan detection...")
    try:
        # Sniff only incoming TCP SYN packets
        sniff(filter="tcp", prn=detect_port_scan, store=0)
    except KeyboardInterrupt:
        print("\nStopping port scan detection. Exiting...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

