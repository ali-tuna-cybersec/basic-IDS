# 🔍 Intrusion Detection System (IDS)  

A **real-time IDS** that monitors network traffic and detects **DoS attacks, port scans, and malicious payloads** using `scapy`. Logs all alerts for analysis.  

---

## 🚀 Features  
✅ **Detects DoS/DDoS attacks** *(packet rate & timing analysis)*  
✅ **Identifies port scans** *(multiple port attempts from the same IP)*  
✅ **Flags suspicious payloads** *(known malicious patterns)*  
✅ **Reduces false positives** *(whitelist & adaptive thresholds)*  
✅ **Logs alerts** to `ids.log`  

---

## ⚙️ Configuration

🔧 Modify detection thresholds in ids.py:

    Port Scan Threshold: PORT_SCAN_THRESHOLD = 10
    DoS Detection: DOS_THRESHOLD = 100
    Time Window: SLIDING_WINDOW_SIZE = 5 seconds

📜 Whitelist trusted IPs inside the script to reduce false positives.

## 🛠️ Installation  
```bash
pip install scapy
git clone https://github.com/yourusername/ids-tool.git
cd ids-tool


