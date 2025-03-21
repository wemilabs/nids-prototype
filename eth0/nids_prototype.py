from scapy.all import *
import time

# Configuration
TIME_WINDOW = 60  # Time window in seconds
PORT_THRESHOLD = 10  # Max unique ports before flagging a port scan
SYN_THRESHOLD = 100  # Max SYN packets before flagging a SYN flood

# Data structures to track traffic
scan_attempts = {}  # Key: (src_ip, dst_ip), Value: list of (port, timestamp)
syn_counts = {}     # Key: (dst_ip, dst_port), Value: list of timestamps

def packet_handler(packet):
    """
    Process each captured packet to detect port scans and SYN floods.
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        current_time = time.time()

        # --- Port Scan Detection ---
        key = (src_ip, dst_ip)
        if key not in scan_attempts:
            scan_attempts[key] = []
        # Add current port with timestamp
        scan_attempts[key].append((dst_port, current_time))
        # Remove entries older than TIME_WINDOW
        scan_attempts[key] = [entry for entry in scan_attempts[key] 
                             if current_time - entry[1] <= TIME_WINDOW]
        # Count unique ports in the window
        unique_ports = set(entry[0] for entry in scan_attempts[key])
        if len(unique_ports) > PORT_THRESHOLD:
            print(f"Potential port scan from {src_ip} to {dst_ip}: "
                  f"{len(unique_ports)} ports scanned")
            scan_attempts[key] = []  # Reset after alert

        # --- SYN Flood Detection ---
        if packet[TCP].flags == 'S':  # Check for SYN flag
            syn_key = (dst_ip, dst_port)
            if syn_key not in syn_counts:
                syn_counts[syn_key] = []
            # Add SYN packet timestamp
            syn_counts[syn_key].append(current_time)
            # Remove old timestamps
            syn_counts[syn_key] = [ts for ts in syn_counts[syn_key] 
                                  if current_time - ts <= TIME_WINDOW]
            if len(syn_counts[syn_key]) > SYN_THRESHOLD:
                print(f"Potential SYN flood to {dst_ip}:{dst_port}: "
                      f"{len(syn_counts[syn_key])} SYN packets")
                syn_counts[syn_key] = []  # Reset after alert

# Start capturing packets on the loopback interface
print("Starting NIDS prototype... Press Ctrl+C to stop.")
sniff(iface="eth0", filter="tcp", prn=packet_handler)