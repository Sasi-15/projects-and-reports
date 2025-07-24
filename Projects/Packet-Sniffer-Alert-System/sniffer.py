from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
import os

# ✅ Load Alert Rules
with open('rules.json') as file:
    rules = json.load(file)

alert_ips = rules.get("alert_ips", [])
alert_ports = rules.get("alert_ports", [])
alert_protocols = rules.get("alert_protocols", [])

# ✅ Create logs folder if it doesn’t exist
if not os.path.exists('logs'):
    os.makedirs('logs')

logfile = open("logs/sniffed-packets-log.txt", "a")

def log_event(message):
    print(message)
    logfile.write(message + "\n")

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        proto = "OTHER"
        src_port = dst_port = None

        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"

        log_event(f"[{proto}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # ✅ Alert System
        if src_ip in alert_ips or dst_ip in alert_ips:
            log_event(f"ALERT ***** Suspicious IP Detected: {src_ip} -> {dst_ip}")

        if dst_port in alert_ports:
            log_event(f"ALERT ***** Suspicious Port Accessed: Port {dst_port}")

        if proto in alert_protocols:
            log_event(f"ALERT ***** Suspicious Protocol Detected: {proto}")

print("✅ Packet Sniffer Started — Monitoring Traffic Live...")
sniff(prn=process_packet, store=0)
