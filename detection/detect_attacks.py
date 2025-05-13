import re
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, ARP

def parse_log_line(line):
    # Supports both:
    # [timestamp] TCP | src -> dst:port
    # [timestamp] ARP | src -> dst
    pattern = r"\[(.*?)\] (\w+) \| (.*?) -> (.*?)(?::(\d+))?$"
    match = re.match(pattern, line.strip())
    if match:
        timestamp_str, proto, src_ip, dst_ip, port = match.groups()
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        port = int(port) if port else None
        return timestamp, proto, src_ip, dst_ip, port
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


def detect_port_scan(logs, threshold=10, time_window=5):
    port_logs = defaultdict(list)  # key: src_ip, value: list of (timestamp, port)
    alerts = []

    for log in logs:
        if log[1] == "TCP" and log[4]:  # log[4] is port
            src_ip = log[2]
            timestamp = log[0]
            port = log[4]
            port_logs[src_ip].append((timestamp, port))

    for ip, records in port_logs.items():
        records.sort()
        for i in range(len(records)):
            window_ports = set()
            start_time = records[i][0]

            for j in range(i, len(records)):
                time_diff = (records[j][0] - start_time).total_seconds()
                if time_diff <= time_window:
                    window_ports.add(records[j][1])
                    if len(window_ports) > threshold:
                        alerts.append(f"[Port Scan] {ip} accessed {len(window_ports)} ports in {time_window}s")
                        break
                else:
                    break
    return alerts




def detect_brute_force(logs, threshold=5, window_seconds=60):
    login_failures = defaultdict(list)
    alerts = []

    for log in logs:
        # Match brute force pattern like: [timestamp] LOGIN_FAIL | IP → message
        if "LOGIN_FAIL" in log[1]:
            try:
                timestamp = datetime.strptime(log[0], "%Y-%m-%d %H:%M:%S.%f")
                src_ip = log[2]
                login_failures[src_ip].append(timestamp)
            except:
                continue

    for ip, attempts in login_failures.items():
        # Count how many attempts happened in the last `window_seconds`
        recent = [t for t in attempts if (attempts[-1] - t).seconds <= window_seconds]
        if len(recent) >= threshold:
            alerts.append(f"[Brute Force] {ip} had {len(recent)} failed logins in {window_seconds}s")
    return alerts

def main():
    with open("logs/captured_packets.log") as f:
        lines = f.readlines()
    logs = [parse_log_line(line) for line in lines if parse_log_line(line)]

    mitm_alerts = detect_mitm(logs)
    ddos_alerts = detect_ddos(logs)
    brute_force_alerts = detect_brute_force(logs)
    # detect_port_scan(logs)

    print("\n=== MITM Alerts ===")
    for alert in mitm_alerts:
        print(alert)

    print("\n=== DDoS Alerts ===")
    for alert in ddos_alerts:
        print(alert)

    
    print("\n=== brute Force Alerts ===")
    for alert in brute_force_alerts:
        print(alert)

    portscan_alerts = detect_port_scan(logs)

    print("\n=== Port Scan Alerts ===")
    for alert in portscan_alerts:
        print(alert)

if __name__ == "__main__":
    main()