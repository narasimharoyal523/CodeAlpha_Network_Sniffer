from scapy.all import *
import pandas as pd

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = str(packet.payload) if packet.haslayer(Raw) else "No payload"
        
        print(f"[+] Packet: {src_ip} → {dst_ip} (Proto: {proto})")
        print(f"    Payload: {payload[:50]}...\n")

print("[*] Starting sniffer (20 packets)...")
sniff(iface="Wi-Fi", prn=packet_callback, store=0, count=20)