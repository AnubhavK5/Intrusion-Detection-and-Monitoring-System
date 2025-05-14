from django.contrib import admin
from .models import ThreatAlert

@admin.register(ThreatAlert)
class ThreatAlertAdmin(admin.ModelAdmin):
    list_display = ('alert_type', 'source_ip', 'timestamp', 'is_resolved')
    list_filter = ('alert_type', 'is_resolved', 'timestamp')
    search_fields = ('source_ip', 'details')
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'
    
    actions = ['mark_as_resolved', 'mark_as_active']
    
    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(is_resolved=True)
        self.message_user(request, f'{updated} alerts marked as resolved.')
    mark_as_resolved.short_description = "Mark selected alerts as resolved"
    
    def mark_as_active(self, request, queryset):
        updated = queryset.update(is_resolved=False)
        self.message_user(request, f'{updated} alerts marked as active.')
    mark_as_active.short_description = "Mark selected alerts as active"