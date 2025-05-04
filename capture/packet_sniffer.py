from scapy.all import sniff, IP, TCP, ARP
from datetime import datetime

def process_packet(pkt):
    proto = "OTHER"
    src_ip = dst_ip = '-'

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "TCP" if pkt.haslayer(TCP) else "IP"

    elif pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        proto = "ARP"

    log_entry = f"[{datetime.now()}] {proto} | {src_ip} -> {dst_ip}\n"
    print(log_entry.strip())
    with open("logs/captured_packets.log", "a") as f:
        f.write(log_entry)



 

def start_sniffing(interface="eth0"):
    sniff(iface=interface, prn=process_packet, store=False)



if __name__ == "__main__":
    start_sniffing("lo")