from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('demo-login/', views.demo_login, name='demo_login'),
    path('simulate-attack/', views.simulate_attack, name='simulate_attack'),
    path('run-detection/', views.run_detection, name='run_detection'),
]