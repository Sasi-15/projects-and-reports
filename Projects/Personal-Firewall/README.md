### PROJECT - Personal Firewall using Python 🧱⚔️

## 📖 Introduction

- This is a simple Python-based Personal Firewall that monitors live network traffic, detects malicious IP addresses and ports, and logs traffic events in real-time.
Perfect for beginners to understand how basic firewalls operate!

---

## 🚀 Features

✅ Packet Sniffing using Scapy

✅ Block traffic by IP or Port

✅ Allow specific safe ports

✅ Live Logging to traffic-log.txt

✅ Editable Rules via rules.json

✅ Easy to understand and customize

---

## 🗂️ Project Structure

Personal-Firewall/
├── firewall.py                # Main Firewall Code
├── rules.json                 # Rules for blocking/allowing traffic
├── logs/
│   └── traffic-log.txt        # Logs captured packets
└── README.md                  # Documentation

---

## ⚙️ How to Use

1️⃣ Install Requirements: pip install scapy
2️⃣ Edit Rules in rules.json:
{
  "block_ips": ["103.88.103.101", "192.168.1.100"],
  "block_ports": [23, 445],
  "allow_ports": [22, 80, 443]
}

3️⃣ Run the Firewall: python firewall.py
4️⃣ View Logs: logs/traffic-log.txt

---

## 📝 Example Output:

✅ TCP: 192.168.1.5:443 → 8.8.8.8:80
❌ BLOCKED IP: 103.88.103.101 → 8.8.8.8
❌ BLOCKED PORT: 192.168.1.5:55600 → 8.8.8.8:445

---

📌 Notes
You can easily edit rules.json anytime to update block/allow lists.

This is a mini-learning project and not a replacement for commercial-grade firewalls like Fortinet/Palo Alto.

---

## 💬 Tools Used

Python 🐍
Scapy 🟣
JSON 🟠
Linux Terminal / Windows CMD

---
