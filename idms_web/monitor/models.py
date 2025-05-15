from django.db import models

class ThreatAlert(models.Model):
    ALERT_TYPES = [
        ('DDOS', 'DDoS Attack'),
        ('PORT_SCAN', 'Port Scanning'),
        ('MITM', 'Man in the Middle'),
        ('BRUTE_FORCE', 'Brute Force'),
    ]
    
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPES, default='DDOS')
    source_ip = models.CharField(max_length=45)  # IPv6 can be up to 45 chars
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.get_alert_type_display()} from {self.source_ip} at {self.timestamp}"
    
    class Meta:
        ordering = ['-timestamp']