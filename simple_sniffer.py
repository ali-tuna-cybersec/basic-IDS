from scapy.all import sniff

# Function to process each packet
def process_packet(packet):
    print(packet.summary())  # Print basic packet details

# Start sniffing packets (requires sudo/admin privileges)
print("Starting packet sniffing... Press Ctrl+C to stop.")
sniff(prn=process_packet, count=10)  # Capture 10 packets
