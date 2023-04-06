"""django_network_automation URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('', views.home, name='home'),
    path('devices/', views.devices, name='devices'),
    path('config/', views.config, name='config'),
    path('verify_config/', views.verify_config, name='verify_config'),
    path('backup_config/', views.backup_config, name='backup_config'),
    path('log/', views.log, name='log'),
    path('mac_arp/', views.mac_arp, name='mac_arp'),
    path('nornir_hosts/', views.nornir_hosts, name='nornir_hosts'),
    path('information_collection/', views.information_collection, name='information_collection'),
    path('mac_location/', views.mac_location, name='mac_location'),
    path('inspection/', views.inspection, name='inspection'),
    path('network_version/', views.network_version, name='network_version'),
    path('FD_SFTP_white/', views.FD_SFTP_white, name='FD_SFTP_white'),
    path('K8S_BGP/', views.K8S_BGP, name='K8S_BGP'),
]

