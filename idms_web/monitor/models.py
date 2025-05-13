from django.db import models

class ThreatAlert(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    attack_type = models.CharField(max_length=50)
    source_ip = models.GenericIPAddressField()
    description = models.TextField()




    def __str__(self):  # ⑦
            return f"{self.attack_type} - {self.source_ip}"