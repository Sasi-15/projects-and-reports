
# Packet Sniffer with Alert System 🚨

A Python-based network monitoring tool that captures live packets and alerts when suspicious traffic (like ICMP) is detected.

## 📌 Features
- Live packet sniffing (TCP, UDP, ICMP)
- Real-time alerts for suspicious protocols
- JSON-based rule configuration
- Traffic logging to a local file

## 🚀 How It Works
1. Starts monitoring network traffic using `scapy`
2. Applies alert rules from `rules.json`
3. Displays alerts in the terminal and saves all packets in `logs/sniffed-packets-log.txt`

## ⚙️ Technologies Used
- Python 3
- scapy
- json, datetime, os

## 🧪 How to Run
```bash
python sniffer.py
```

## 📂 Folder Structure
```
Packet-Sniffer-Alert-System/
├── sniffer.py
├── rules.json
├── logs/
│   └── sniffed-packets-log.txt
├── README.md
├── Packet-Sniffer-Report.pdf

```

## 📄 Report
Check `Packet-Sniffer-Report.pdf` for complete technical documentation.

---

🛡️ Built as part of the Elevate Labs Internship Project Phase.
