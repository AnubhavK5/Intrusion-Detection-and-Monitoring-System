from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('demo-login/', views.demo_login, name='demo_login'),
    path('simulate-attack/', views.simulate_attack, name='simulate_attack'),
    path('run-detection/', views.run_detection, name='run_detection'),
    # path('alert/<int:alert_id>/resolve/', views.resolve_alert, name='resolve_alert'),
    # path('alert/<int:alert_id>/details/', views.alert_details, name='alert_details'),
    path('alerts/resolve-all/', views.resolve_all_alerts, name='resolve_all_alerts'),
]