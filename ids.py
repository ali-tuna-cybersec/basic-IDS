from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from collections import defaultdict
import time
import statistics

# Thresholds and time windows
PORT_SCAN_THRESHOLD = 15  # More than 15 unique ports in 5 seconds
DOS_THRESHOLD = 500  # More than 500 packets from a single IP in 5 seconds
TIME_WINDOW = 5  # 5-second window for analysis

# Data storage
connection_attempts = defaultdict(list)  # Stores timestamps of connections per IP
packet_counts = defaultdict(list)  # Stores packet timestamps per IP
syn_flood_counts = defaultdict(int)  # Counts SYN packets per IP
icmp_flood_counts = defaultdict(int)  # Counts ICMP packets per IP

# Whitelist for trusted IPs (example)
WHITELIST = {'192.168.1.1', '10.0.0.1'}

# Function to detect threats
def detect_threats(packet):
    if IP in packet:
        src_ip = packet[IP].src
        timestamp = time.time()

        if src_ip in WHITELIST:
            return

        # Port Scan Detection
        if TCP in packet:
            dst_port = packet[TCP].dport
            connection_attempts[src_ip].append((timestamp, dst_port))
            connection_attempts[src_ip] = [
                (t, p) for t, p in connection_attempts[src_ip] if timestamp - t < TIME_WINDOW
            ]
            unique_ports = {p for _, p in connection_attempts[src_ip]}
            if len(unique_ports) > PORT_SCAN_THRESHOLD:
                print(f"⚠️ Possible Port Scan Detected from {src_ip} (Scanned {len(unique_ports)} ports)")

            # SYN Flood Detection
            if packet[TCP].flags & 0x02:  # SYN flag is set
                syn_flood_counts[src_ip] += 1
                if syn_flood_counts[src_ip] > DOS_THRESHOLD:
                    print(f"⚠️ Possible SYN Flood Attack Detected from {src_ip}")

        # ICMP Flood Detection
        if ICMP in packet:
            icmp_flood_counts[src_ip] += 1
            if icmp_flood_counts[src_ip] > DOS_THRESHOLD:
                print(f"⚠️ Possible ICMP Flood Attack Detected from {src_ip}")

        # General DDoS Detection
        packet_counts[src_ip].append(timestamp)
        packet_counts[src_ip] = [t for t in packet_counts[src_ip] if timestamp - t < TIME_WINDOW]
        
        if len(packet_counts[src_ip]) > DOS_THRESHOLD:
            # Calculate packet rate
            packet_rate = len(packet_counts[src_ip]) / TIME_WINDOW
            # Calculate packet inter-arrival times
            inter_arrival_times = [j-i for i, j in zip(packet_counts[src_ip][:-1], packet_counts[src_ip][1:])]
            
            if inter_arrival_times:
                # Check for unusually consistent inter-arrival times (potential botnet behavior)
                if statistics.stdev(inter_arrival_times) < 0.1:
                    print(f"⚠️ Possible DDoS Attack Detected from {src_ip} (Consistent pattern, rate: {packet_rate:.2f} packets/sec)")
                elif packet_rate > DOS_THRESHOLD / TIME_WINDOW:
                    print(f"⚠️ High Traffic Volume Detected from {src_ip} (Rate: {packet_rate:.2f} packets/sec)")

        # Payload Analysis (example)
        if Raw in packet:
            payload = packet[Raw].load.lower()
            if b"union select" in payload or b"' or '1'='1" in payload:
                print(f"⚠️ Possible SQL Injection Attempt Detected from {src_ip}")
            elif b"<script>" in payload or b"javascript:" in payload:
                print(f"⚠️ Possible XSS Attempt Detected from {src_ip}")

# Start Sniffing
print("🔍 Enhanced IDS is monitoring traffic... Press Ctrl+C to stop.")
sniff(filter="ip", prn=detect_threats, store=False)
