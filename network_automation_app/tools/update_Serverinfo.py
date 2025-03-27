from nornir.core.filter import F
from ..models import Version, Device, Interface, ServerIp
import netmiko
from netmiko import ConnectHandler, SCPConn
import os, sys, pickle
import django
from django.utils import timezone
from datetime import datetime
import os, re, openpyxl, time
from django.conf import settings
from django.conf import global_settings
from nornir import InitNornir
from nornir_netmiko import netmiko_send_command, netmiko_send_config, netmiko_save_config
import requests
from network_automation_app.models import Device, Log
 
def Synchronize_cmdb(ip):
    selected_ips = ip 
    selected_ips_list = selected_ips.split(',')
    response = requests.get('https://cmdb.u51-inc.com/opsadmin/api/v2/server/getserverinfolist?pageSize=10000&status=working_online&macCategory=物理机')
    data = response.json()
    if "rows" in data:
        servers = data["rows"]
        api_ips = {server.get("ip"): server.get("sn") for server in servers}
    for ip_list, sn in api_ips.items():
        if selected_ips not in api_ips:
            ServerIp.objects.filter(ip_address=selected_ips).delete()
        else:
            pass
    for ip_list, sn in api_ips.items():
        if ip_list not in selected_ips_list:
            sn = api_ips[ip_list]
            ServerIp.objects.create(ip_address=ip_list, SN=sn)
        else:
            pass
