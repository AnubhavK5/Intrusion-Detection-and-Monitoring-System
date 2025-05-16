from django.shortcuts import render, redirect, get_object_or_404
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
    target_ip = "192.168.1.1"
    
    common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389]  # Common ports to scan
    
    with open(log_path, "a") as f:
        for port in common_ports:
            timestamp = timezone.now()
            log_entry = f"[{timestamp}] TCP | {attacker_ip} -> {target_ip}:{port}\n"
            f.write(log_entry)

def simulate_mitm_attack():
    """Simulate a MITM attack by adding ARP entries to the log file"""
    log_path = Path(__file__).resolve().parent.parent.parent / 'logs' / 'captured_packets.log'
    attacker_ip = f"192.168.1.{random.randint(2, 254)}"
    
    with open(log_path, "a") as f:
        timestamp = timezone.now()
        # Generate more ARP traffic for better detection
        for target_id in range(2, 7):  # Target 5 different IPs
            target_ip = f"192.168.1.{target_id}"
            # Send multiple ARP packets for each target
            for _ in range(3):  # 3 packets per target = 15 total
                log_entry = f"[{timestamp}] ARP | {attacker_ip} -> {target_ip}\n"
                f.write(log_entry)
                # Small delay to ensure unique timestamps
                time.sleep(0.001)

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
        if not line.strip():
            continue
            
        if line.startswith('[PORT_SCAN]'):
            parts = line[11:].split(' ', 1)  # Skip [PORT_SCAN]
            if len(parts) >= 2:
                source_ip = parts[0]
                if not ThreatAlert.objects.filter(
                    alert_type='PORT_SCAN',
                    source_ip=source_ip,
                    is_resolved=False
                ).exists():
                    create_alert('PORT_SCAN', source_ip, parts[1])
        
        elif line.startswith('[MITM]'):
            parts = line[6:].split(' ', 1)  # Skip [MITM]
            if len(parts) >= 2:
                source_ip = parts[0]
                if not ThreatAlert.objects.filter(
                    alert_type='MITM',
                    source_ip=source_ip,
                    is_resolved=False
                ).exists():
                    create_alert('MITM', source_ip, parts[1])
        
        elif line.startswith('[DDoS]'):
            parts = line.split(' ', 3)
            if len(parts) >= 4:
                source_ip = parts[3].split(':')[0]
                create_alert('DDOS', source_ip, line[6:])
        
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

def resolve_alert(request, alert_id):
    """Mark an alert as resolved"""
    if request.method == 'POST':
        alert = get_object_or_404(ThreatAlert, id=alert_id)
        alert.is_resolved = True
        alert.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def alert_details(request, alert_id):
    """Get alert details"""
    alert = get_object_or_404(ThreatAlert, id=alert_id)
    details = {
        'id': alert.id,
        'type': alert.alert_type,
        'source_ip': alert.source_ip,
        'details': alert.details,
        'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'is_resolved': alert.is_resolved
    }
    return JsonResponse(details)

def resolve_all_alerts(request):
    """Mark all alerts as resolved"""
    if request.method == 'POST':
        try:
            # Clear all alerts from database
            ThreatAlert.objects.all().delete()
            
            # Clear the log file
            log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs', 'captured_packets.log')
            with open(log_path, 'w') as f:
                f.write('')  # Clear the file
                
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})