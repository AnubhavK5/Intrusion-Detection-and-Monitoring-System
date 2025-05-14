from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from .models import ThreatAlert
import subprocess
import os
import sys
import random
import time
import socket
from pathlib import Path

def dashboard(request):
    """Main dashboard view showing threat alerts and options to simulate attacks"""
    alerts = ThreatAlert.objects.all()
    context = {
        'alerts': alerts,
        'active_page': 'dashboard'
    }
    return render(request, 'monitor/dashboard.html', context)

def demo_login(request):
    """Demo login page to simulate brute force attempts"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # For demo purposes, only 'admin'/'password' is valid
        if username == 'admin' and password == 'password':
            messages.success(request, 'Login successful!')
            return redirect('dashboard')
        else:
            # Log failed login attempt
            log_failed_login(request.META.get('REMOTE_ADDR', '127.0.0.1'))
            messages.error(request, 'Invalid credentials')
    
    return render(request, 'monitor/demo_login.html', {'active_page': 'demo_login'})

def log_failed_login(ip_address):
    """Log failed login attempts to the packet log"""
    timestamp = timezone.now()
    log_entry = f"[{timestamp}] LOGIN_FAIL | {ip_address} -> login attempt failed\n"
    
    log_path = Path(__file__).resolve().parent.parent.parent / 'logs' / 'captured_packets.log'
    with open(log_path, "a") as f:
        f.write(log_entry)

def simulate_attack(request):
    """API endpoint to simulate different types of attacks"""
    attack_type = request.GET.get('type', '')
    
    if attack_type == 'ddos':
        simulate_ddos_attack()
        return JsonResponse({'status': 'success', 'message': 'DDoS simulation started'})
    
    elif attack_type == 'port_scan':
        simulate_port_scan()
        return JsonResponse({'status': 'success', 'message': 'Port scan simulation started'})
    
    elif attack_type == 'mitm':
        simulate_mitm_attack()
        return JsonResponse({'status': 'success', 'message': 'MITM simulation started'})
    
    elif attack_type == 'brute_force':
        simulate_brute_force()
        return JsonResponse({'status': 'success', 'message': 'Brute force simulation started'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid attack type'})

def simulate_ddos_attack():
    """Simulate a DDoS attack by adding entries to the log file"""
    log_path = Path(__file__).resolve().parent.parent.parent / 'logs' / 'captured_packets.log'
    attacker_ip = f"192.168.1.{random.randint(2, 254)}"
    
    with open(log_path, "a") as f:
        for _ in range(150):  # Generate 150 packets to trigger DDoS detection
            timestamp = timezone.now()
            target_port = random.randint(1, 65535)
            log_entry = f"[{timestamp}] TCP | {attacker_ip} -> 192.168.1.1:{target_port}\n"
            f.write(log_entry)

def simulate_port_scan():
    """Simulate a port scan by adding entries to the log file"""
    log_path = Path(__file__).resolve().parent.parent.parent / 'logs' / 'captured_packets.log'
    attacker_ip = f"192.168.1.{random.randint(2, 254)}"
    
    with open(log_path, "a") as f:
        for port in range(20, 30):  # Scan ports 20-29
            timestamp = timezone.now()
            log_entry = f"[{timestamp}] TCP | {attacker_ip} -> 192.168.1.1:{port}\n"
            f.write(log_entry)

def simulate_mitm_attack():
    """Simulate a MITM attack by adding ARP entries to the log file"""
    log_path = Path(__file__).resolve().parent.parent.parent / 'logs' / 'captured_packets.log'
    attacker_ip = f"192.168.1.{random.randint(2, 254)}"
    
    with open(log_path, "a") as f:
        for target_ip in [f"192.168.1.{i}" for i in range(2, 10)]:
            timestamp = timezone.now()
            log_entry = f"[{timestamp}] ARP | {attacker_ip} -> {target_ip}\n"
            f.write(log_entry)

def simulate_brute_force():
    """Simulate a brute force attack by adding failed login entries"""
    log_path = Path(__file__).resolve().parent.parent.parent / 'logs' / 'captured_packets.log'
    attacker_ip = f"192.168.1.{random.randint(2, 254)}"
    
    with open(log_path, "a") as f:
        for _ in range(15):  # 15 failed login attempts
            timestamp = timezone.now()
            log_entry = f"[{timestamp}] LOGIN_FAIL | {attacker_ip} -> login attempt failed\n"
            f.write(log_entry)

def run_detection(request):
    """Run the attack detection script and store results in database"""
    base_dir = Path(__file__).resolve().parent.parent.parent
    detection_script = base_dir / 'detection' / 'detect_attacks.py'
    
    try:
        # Run the detection script
        detection_output = subprocess.check_output([sys.executable, detection_script], 
                                                   stderr=subprocess.STDOUT, text=True)
        
        # Process the output to create ThreatAlert objects
        process_detection_output(detection_output)
        
        return JsonResponse({'status': 'success', 'message': 'Detection completed'})
    except subprocess.CalledProcessError as e:
        return JsonResponse({'status': 'error', 'message': f'Detection failed: {e.output}'})

def process_detection_output(output):
    """Parse detection script output and create ThreatAlert objects"""
    lines = output.split('\n')
    
    for line in lines:
        if line.startswith('[MITM]'):
            parts = line.split(' ', 2)
            if len(parts) >= 3:
                create_alert('MITM', parts[1], parts[2])
        
        elif line.startswith('[DDoS]'):
            parts = line.split(' ', 3)
            if len(parts) >= 4:
                source_ip = parts[3].split(':')[0]
                create_alert('DDOS', source_ip, line[6:])
        
        elif line.startswith('[PORT_SCAN]'):
            parts = line.split(' ', 2)
            if len(parts) >= 3:
                source_ip = parts[1]
                create_alert('PORT_SCAN', source_ip, line[11:])
        
        elif line.startswith('[BRUTE_FORCE]'):
            parts = line.split(' ', 2)
            if len(parts) >= 3:
                source_ip = parts[1]
                create_alert('BRUTE_FORCE', source_ip, line[13:])

def create_alert(alert_type, source_ip, details):
    """Create a new ThreatAlert object"""
    ThreatAlert.objects.create(
        alert_type=alert_type,
        source_ip=source_ip,
        details=details
    )