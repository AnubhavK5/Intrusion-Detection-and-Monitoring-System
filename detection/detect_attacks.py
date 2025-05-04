import re
from collections import defaultdict

def parse_log_line(line):
    pattern = r"\[(.*?)\] (\w+) \| (.*?) -> (.*?)\n?"
    match = re.match(pattern, line)
    if match:
        timestamp, proto, src_ip, dst_ip = match.groups()
        return timestamp, proto, src_ip, dst_ip
    return None

def detect_mitm(logs):
    arp_sources = defaultdict(set)
    alerts = []

    for log in logs:
        if log[1] == "ARP":
            src_ip = log[2]
            dst_ip = log[3]
            arp_sources[src_ip].add(dst_ip)
            if len(arp_sources[src_ip]) > 1:
                alerts.append(f"[MITM] {src_ip} sending ARP replies to multiple destinations: {arp_sources[src_ip]}")
    return alerts

def detect_ddos(logs, threshold=100):
    ip_count = defaultdict(int)
    alerts = []

    for log in logs:
        if log[1] in ["IP", "TCP"]:
            src_ip = log[2]
            ip_count[src_ip] += 1

    for ip, count in ip_count.items():
        if count > threshold:
            alerts.append(f"[DDoS] High packet count from {ip}: {count}")
    return alerts

def main():
    with open("logs/captured_packets.log") as f:
        lines = f.readlines()
    logs = [parse_log_line(line) for line in lines if parse_log_line(line)]

    mitm_alerts = detect_mitm(logs)
    ddos_alerts = detect_ddos(logs)

    print("\n=== MITM Alerts ===")
    for alert in mitm_alerts:
        print(alert)

    print("\n=== DDoS Alerts ===")
    for alert in ddos_alerts:
        print(alert)

if __name__ == "__main__":
    main()