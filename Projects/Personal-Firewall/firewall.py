from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from datetime import datetime

# Load firewall rules from JSON
with open('rules.json', 'r') as f:
    rules = json.load(f)

block_ips = rules.get("block_ips", [])
block_ports = rules.get("block_ports", [])
allow_ports = rules.get("allow_ports", [])

log_file = 'logs/traffic-log.txt'

def log_event(message):
    with open(log_file, 'a') as f:
        f.write(f"{datetime.now()} - {message}\n")
    print(message)

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if ip_src in block_ips:
            log_event(f" BLOCKED IP: {ip_src} to {ip_dst}")
            return

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            if dport in block_ports:
                log_event(f" BLOCKED PORT: {ip_src}:{sport} to {ip_dst}:{dport}")
                return
            if allow_ports and dport not in allow_ports:
                log_event(f" BLOCKED (Not in Allow List): {ip_src}:{sport} to {ip_dst}:{dport}")
                return

            log_event(f" TCP: {ip_src}:{sport} to {ip_dst}:{dport}")

        elif packet.haslayer(UDP):
            log_event(f" UDP Packet from {ip_src} to {ip_dst}")

        elif packet.haslayer(ICMP):
            log_event(f" ICMP (Ping): {ip_src} to {ip_dst}")

print("Personal Firewall Started — Monitoring Network Traffic...")
sniff(prn=process_packet, store=False)
