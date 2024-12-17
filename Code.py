from scapy.all import sniff, TCP
from collections import defaultdict
import threading
import time
import subprocess

#TO-DO 
"""
***Needs Testing*** Need to create function that unblocks ips after a certain amount of time as most attackers will rotate IPs 
Need to create fucntion that replys to the attackers SYN packet with a SYN+ACK packet with text in it. 
"""

# Threshold settings
PORT_SCAN_THRESHOLD = 10  # Number of ports scanned to trigger a block
TIME_WINDOW = 10  # Time window in seconds to detect port scanning
BLOCK_DURATION = 300 # Time the to keep IP Blocked (5 mins) **** NEED TO CHANGE AFTER TESTING ****

# Data structures to track port scanning
ip_scan_activity = defaultdict(list)  # Tracks IPs and the ports they're scanning
blocked_ips = {}  # Keep track of already blocked IPs and there time stamp 

def block_ip(ip_address):
    """
    Block the given IP address using iptables.
    """
    if ip_address not in blocked_ips:
        print(f"[!] Blocking IP: {ip_address}")
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True) #Creates Rule that drops packet from IP 
            blocked_ips[ip_address] = time.time()  # Record the blocked ip and timestamp 
            print(f"[+] Successfully blocked IP: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to block IP: {ip_address}. Error: {e}")
    else:
        print(f"[!] IP {ip_address} is already blocked.")

def unblock_ips():
    """
    Unblocks IP after there block duration time is up.
    """
    while True:
        current_time = time.time()
        #checks if enough time has passed to unblock IP
        check_if_unblock = [
            ip for ip, block_time in blocked_ips.items()
            if current_time - block_time >= BLOCK_DURATION 
        ]
        for ip in check_if_unblock:
            try:
                print(f"[!] Unblocking IP: {ip}")
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)  # Removes block rule
                del blocked_ips[ip]  # Remove from the blocked IPs list
                print(f"[+] Successfully unblocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                print(f"[-] Failed to unblock IP: {ip}. Error: {e}")
        
        time.sleep(60)  # Check for IPs to unblock every minute 

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
        scanned_ports = {entry[0] for entry in ip_scan_activity[source_ip]}  # Creates new list that keeps track of scanned ports and is used as a counter
        if len(scanned_ports) > PORT_SCAN_THRESHOLD:
            print(f"[!] Detected port scan from {source_ip}. Scanned {len(scanned_ports)} ports.")
            block_ip(source_ip)

def main():
    print("Starting port scan detection...")
    #starts daemon thread to run in the background for unblocking IPs
    unblock_thread = threading.Thread(target=unblock_ips(), daemon=True) 
    unblock_thread.start()

    try:
        # Sniff only incoming TCP SYN packets
        sniff(filter="tcp", prn=detect_port_scan, store=0)
    except KeyboardInterrupt:
        print("\nStopping port scan detection. Exiting...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

