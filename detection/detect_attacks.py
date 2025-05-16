# import re
# import time
# from collections import defaultdict
# from scapy.all import sniff, IP, TCP, ARP

# def parse_log_line(line):
#     # Supports both:
#     # [timestamp] TCP | src -> dst:port
#     # [timestamp] ARP | src -> dst
#     pattern = r"\[(.*?)\] (\w+) \| (.*?) -> (.*?)(?::(\d+))?$"
#     match = re.match(pattern, line.strip())
#     if match:
#         timestamp_str, proto, src_ip, dst_ip, port = match.groups()
#         timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
#         port = int(port) if port else None
#         return timestamp, proto, src_ip, dst_ip, port
#     return None


# def detect_mitm(logs):
#     arp_sources = defaultdict(set)
#     alerts = []

#     for log in logs:
#         if log[1] == "ARP":
#             src_ip = log[2]
#             dst_ip = log[3]
#             arp_sources[src_ip].add(dst_ip)
#             if len(arp_sources[src_ip]) > 1:
#                 alerts.append(f"[MITM] {src_ip} sending ARP replies to multiple destinations: {arp_sources[src_ip]}")
#     return alerts

# def detect_ddos(logs, threshold=100):
#     ip_count = defaultdict(int)
#     alerts = []

#     for log in logs:
#         if log[1] in ["IP", "TCP"]:
#             src_ip = log[2]
#             ip_count[src_ip] += 1

#     for ip, count in ip_count.items():
#         if count > threshold:
#             alerts.append(f"[DDoS] High packet count from {ip}: {count}")
#     return alerts


# def detect_port_scan(logs, threshold=10, time_window=5):
#     port_logs = defaultdict(list)  # key: src_ip, value: list of (timestamp, port)
#     alerts = []

#     for log in logs:
#         if log[1] == "TCP" and log[4]:  # log[4] is port
#             src_ip = log[2]
#             timestamp = log[0]
#             port = log[4]
#             port_logs[src_ip].append((timestamp, port))

#     for ip, records in port_logs.items():
#         records.sort()
#         for i in range(len(records)):
#             window_ports = set()
#             start_time = records[i][0]

#             for j in range(i, len(records)):
#                 time_diff = (records[j][0] - start_time).total_seconds()
#                 if time_diff <= time_window:
#                     window_ports.add(records[j][1])
#                     if len(window_ports) > threshold:
#                         alerts.append(f"[Port Scan] {ip} accessed {len(window_ports)} ports in {time_window}s")
#                         break
#                 else:
#                     break
#     return alerts




# def detect_brute_force(logs, threshold=5, window_seconds=60):
#     login_failures = defaultdict(list)
#     alerts = []

#     for log in logs:
#         # Match brute force pattern like: [timestamp] LOGIN_FAIL | IP → message
#         if "LOGIN_FAIL" in log[1]:
#             try:
#                 timestamp = datetime.strptime(log[0], "%Y-%m-%d %H:%M:%S.%f")
#                 src_ip = log[2]
#                 login_failures[src_ip].append(timestamp)
#             except:
#                 continue

#     for ip, attempts in login_failures.items():
#         # Count how many attempts happened in the last `window_seconds`
#         recent = [t for t in attempts if (attempts[-1] - t).seconds <= window_seconds]
#         if len(recent) >= threshold:
#             alerts.append(f"[Brute Force] {ip} had {len(recent)} failed logins in {window_seconds}s")
#     return alerts

# def main():
#     with open("logs/captured_packets.log") as f:
#         lines = f.readlines()
#     logs = [parse_log_line(line) for line in lines if parse_log_line(line)]

#     mitm_alerts = detect_mitm(logs)
#     ddos_alerts = detect_ddos(logs)
#     brute_force_alerts = detect_brute_force(logs)
#     # detect_port_scan(logs)

#     print("\n=== MITM Alerts ===")
#     for alert in mitm_alerts:
#         print(alert)

#     print("\n=== DDoS Alerts ===")
#     for alert in ddos_alerts:
#         print(alert)

    
#     print("\n=== brute Force Alerts ===")
#     for alert in brute_force_alerts:
#         print(alert)

#     portscan_alerts = detect_port_scan(logs)

#     print("\n=== Port Scan Alerts ===")
#     for alert in portscan_alerts:
#         print(alert)

# if __name__ == "__main__":
#     main()

import re
import os
from collections import defaultdict
from datetime import datetime, timedelta

def parse_log_line(line):
    """Parse a log line into components based on its format"""
    # Match standard packet logs
    pattern = r"\[(.*?)\] (\w+) \| (.*?) -> (.*?)\n?"
    match = re.match(pattern, line)
    if match:
        timestamp_str, proto, src_ip, dst_ip = match.groups()
        # Parse timestamp
        try:
            timestamp = datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            timestamp = datetime.now()
        
        # Handle port information if present
        port = None
        if ':' in dst_ip:
            dst_parts = dst_ip.split(':')
            dst_ip = dst_parts[0]
            if len(dst_parts) > 1:
                try:
                    port = int(dst_parts[1])
                except ValueError:
                    port = None
        
        return timestamp, proto, src_ip, dst_ip, port
    
    # Match login failure logs
    login_pattern = r"\[(.*?)\] LOGIN_FAIL \| (.*?) -> (.*?)\n?"
    login_match = re.match(login_pattern, line)
    if login_match:
        timestamp_str, src_ip, message = login_match.groups()
        # Parse timestamp
        try:
            timestamp = datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            timestamp = datetime.now()
        
        return timestamp, "LOGIN_FAIL", src_ip, "auth_service", None
    
    return None

def detect_mitm(logs):
    """Detect potential MITM attacks based on ARP traffic patterns"""
    arp_sources = defaultdict(set)
    alerts = []

    for log in logs:
        timestamp, proto, src_ip, dst_ip, _ = log
        if proto == "ARP":
            arp_sources[src_ip].add(dst_ip)
            if len(arp_sources[src_ip]) > 5:  # Consider it suspicious if sending to multiple targets
                alerts.append(f"[MITM] {src_ip} sending ARP replies to multiple destinations: {', '.join(list(arp_sources[src_ip])[:5])}...")
    return alerts

def detect_ddos(logs, threshold=100):
    """Detect potential DDoS attacks based on high packet counts"""
    ip_count = defaultdict(int)
    alerts = []

    for log in logs:
        timestamp, proto, src_ip, dst_ip, _ = log
        if proto in ["IP", "TCP"]:
            ip_count[src_ip] += 1

    for ip, count in ip_count.items():
        if count > threshold:
            alerts.append(f"[DDoS] High packet count from {ip}: {count} packets")
    return alerts

def detect_port_scan(logs, threshold=5, time_window=60):
    """Detect port scanning based on connections to multiple ports in a short time"""
    scanner_ports = defaultdict(lambda: defaultdict(list))
    alerts = []

    for log in logs:
        timestamp, proto, src_ip, dst_ip, port = log
        if proto == "TCP" and port is not None:
            scanner_ports[src_ip][dst_ip].append((timestamp, port))
    
    for src_ip, targets in scanner_ports.items():
        for dst_ip, connections in targets.items():
            # Sort connections by timestamp
            connections.sort(key=lambda x: x[0])
            
            # Check if multiple ports were scanned within the time window
            for i in range(len(connections)):
                start_time = connections[i][0]
                end_time = start_time + timedelta(seconds=time_window)
                
                # Count ports scanned within window
                ports_in_window = set()
                for conn_time, port in connections:
                    if start_time <= conn_time <= end_time:
                        ports_in_window.add(port)
                
                if len(ports_in_window) >= threshold:
                    ports_str = ", ".join(str(p) for p in sorted(list(ports_in_window)[:10]))
                    alerts.append(f"[PORT_SCAN] {src_ip} scanned {len(ports_in_window)} ports on {dst_ip} within {time_window}s. Sample ports: {ports_str}...")
                    break  # Only report once per src-dst pair
    
    return alerts

def detect_brute_force(logs, threshold=5, time_window=300):
    """Detect brute force attacks based on multiple login failures"""
    login_attempts = defaultdict(list)
    alerts = []

    for log in logs:
        timestamp, proto, src_ip, dst_ip, _ = log
        if proto == "LOGIN_FAIL":
            login_attempts[src_ip].append(timestamp)
    
    for src_ip, attempts in login_attempts.items():
        # Sort attempts by timestamp
        attempts.sort()
        
        for i in range(len(attempts)):
            start_time = attempts[i]
            end_time = start_time + timedelta(seconds=time_window)
            
            # Count attempts within window
            attempts_in_window = 0
            for attempt_time in attempts:
                if start_time <= attempt_time <= end_time:
                    attempts_in_window += 1
            
            if attempts_in_window >= threshold:
                alerts.append(f"[BRUTE_FORCE] {src_ip} made {attempts_in_window} failed login attempts within {time_window}s")
                break  # Only report once per IP
    
    return alerts

def main():
    """Main function to run detection algorithms on log file"""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_path = os.path.join(project_root, "logs", "captured_packets.log")

    with open(log_path, "r") as f:
        lines = f.readlines()
    # Captcha*
    logs = [parse_log_line(line) for line in lines]
    logs = [log for log in logs if log is not None]  # Filter out None values

    mitm_alerts = detect_mitm(logs)
    ddos_alerts = detect_ddos(logs)
    port_scan_alerts = detect_port_scan(logs)
    brute_force_alerts = detect_brute_force(logs)

    print("\n=== MITM Alerts ===")
    for alert in mitm_alerts:
        print(alert)

    print("\n=== DDoS Alerts ===")
    for alert in ddos_alerts:
        print(alert)
        
    print("\n=== Port Scan Alerts ===")
    for alert in port_scan_alerts:
        print(alert)
        
    print("\n=== Brute Force Alerts ===")
    for alert in brute_force_alerts:
        print(alert)

if __name__ == "__main__":
    main()