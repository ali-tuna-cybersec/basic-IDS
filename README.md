🔍 Intrusion Detection System (IDS)

A lightweight real-time IDS that detects DoS attacks, port scans, and malicious payloads using scapy. Logs all alerts for analysis.
🚀 Features

✅ Detects DoS/DDoS attacks (packet rate & timing analysis)
✅ Identifies port scans (multiple port attempts from same IP)
✅ Flags suspicious payloads (known malicious patterns)
✅ Reduces false positives (whitelist & adaptive thresholds)
✅ Logs alerts to ids.log
🛠️ Installation

pip install scapy
git clone https://github.com/yourusername/ids-tool.git
cd ids-tool

🚀 Usage

Run the IDS:

sudo python3 ids.py

Stop with Ctrl + C
📂 Example Logs

⚠️ Port Scan - IP: 192.168.1.100, Ports: 15  
🚨 DoS Attack - IP: 203.0.113.50, Rate: 105 pkt/sec  
⚠️ Suspicious Payload - IP: 185.220.101.6, Pattern: "exploit"  

⚙️ Configuration

Edit ids.py to adjust detection thresholds.
