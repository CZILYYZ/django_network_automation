from nornir.core.filter import F
from ..models import Version, Device
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

from network_automation_app.models import Device, Log
 
def collect_version(ip,platform):
    os.chdir(global_settings.inventory_path)
    HW_version = re.compile(r'oftware, Version \S+ \(\S+ (\S+)\)', re.M)
    CS_version = re.compile(r', Version (\S+) RELEASE', re.M)
    F5_version = re.compile(r'Version +(\S+)', re.M)
    NS_version = re.compile(r'NetScaler (\S+):', re.M)
    FT_version = re.compile(r' (\S+),build', re.M)
    HW_patch = re.compile(r'Patch Version: (\S+)', re.M)
    F5_patch = re.compile(r'Build +(\S+)', re.M)
    NS_patch = re.compile(r'Build (\S+),', re.M)
    FT_patch = re.compile(r'build(\S+) ', re.M)
    HW_model = re.compile(r'HUAWEI (\S+) .*uptime', re.M)
    CS_model = re.compile(r'cisco (\S+) \(', re.M)
    F5_model = re.compile(r'Product +(\S+)', re.M)
    NS_model = re.compile(r'(\S+) NS', re.M)
    FT_model = re.compile(r'Version: (\S+) ', re.M)
    HW_USG_model = re.compile(r'(\S+) uptime', re.M)
    uptime = re.compile(r'uptime is (\S+ \w+)', re.M)
    F5_uptime = re.compile(r'up (\S+ \S+),', re.M)
    NS_uptime = re.compile(r'Date: (.*)   \(', re.M)
    FT_uptime = re.compile(r'Uptime: (\S+ \S+),', re.M)
    nr = InitNornir(config_file="config.yaml")
    device = nr.filter(F(hostname=ip))
    if platform == 'huawei':
        def HW(task):
            task.run(netmiko_send_command, command_string='dis version')
        HW = device.run(task=HW)
        for sw in HW.keys():
            output = HW[sw][(1)].result
            HW_Version = HW_version.findall(output)
            Uptime = uptime.findall(output)
            HW_Patch = HW_patch.findall(output)
            Model = HW_model.findall(output)
            device_id = Device.objects.filter(ip_address=ip)[0]  # 假设这里获取设备的id
            version_q = Version.objects.filter(dev=device_id)
            if HW_Patch:
                HW_Patch = HW_patch.findall(output)
            else:
                HW_Patch = ['None']
            if Model:
                Model = HW_model.findall(output)
            else:
                Model = HW_USG_model.findall(output)

            if version_q:
                version = version_q[0]
                version.version = HW_Version[0]
                version.patch = HW_Patch[0]
                version.series = Model[0]
                version.uptime = Uptime[0]
                version.save()
            else:
                version = Version(dev=device_id,
                                  version=HW_Version[0],
                                  patch=HW_Patch[0],
                                  series=Model[0],
                                  uptime=Uptime[0],
                                  )
                version.save()
    elif platform == 'cisco_ios' or platform == 'cisco_ios_telnet':
        def CS(task):
            task.run(netmiko_send_command, command_string='show version')
        CS = device.run(task=CS)
        for sw in CS.keys():
            output = CS[sw][(1)].result
            CS_Version = CS_version.findall(output)
            Uptime = uptime.findall(output)
            Model = CS_model.findall(output)
            device_id = Device.objects.filter(ip_address=ip)[0]  # 假设这里获取设备的id
            version_q = Version.objects.filter(dev=device_id)
            CS_Patch = ['None']
            Model = CS_model.findall(output)

            if version_q:
                version = version_q[0]
                version.version = CS_Version[0]
                version.patch = CS_Patch[0]
                version.series = Model[0]
                version.uptime = Uptime[0]
                version.save()
            else:
                version = Version(dev=device_id,
                                  version=CS_Version[0],
                                  patch=CS_Patch[0],
                                  series=Model[0],
                                  uptime=Uptime[0],
                                  )
                version.save()
    elif platform == 'f5_tmsh':
        netmiko_options = nr.inventory.defaults.connection_options.get("netmiko", {})
        extras = getattr(netmiko_options, "extras", {})
        secret = extras.get("secret", "")
        # 获取用户名、密码和秘密密钥
        username = nr.inventory.defaults.username
        password = nr.inventory.defaults.password
        connection_info = {
            'device_type': 'f5_linux',
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret,
        }
        commands = ['uptime', 'tmsh show sys version']  
        output = ""
        with ConnectHandler(**connection_info) as dev_connection:
            for c in commands:
                output = output + dev_connection.send_command(c)
        HW_Version = F5_version.findall(output)
        Uptime = F5_uptime.findall(output)
        HW_Patch = F5_patch.findall(output)
        Model = F5_model.findall(output)
        device_id = Device.objects.filter(ip_address=ip)[0]  # 假设这里获取设备的id
        version_q = Version.objects.filter(dev=device_id)
        if version_q:
            version = version_q[0]
            version.version = HW_Version[0]
            version.patch = HW_Patch[0]
            version.series = Model[0]
            version.uptime = Uptime[0]
            version.save()
        else:
            version = Version(dev = device_id,
                              version = HW_Version[0],
                              patch = HW_Patch[0],
                              series = Model[0],
                              uptime = Uptime[0],
                              )
            version.save()

    elif platform == 'netscaler':
        netmiko_options = nr.inventory.defaults.connection_options.get("netmiko", {})
        extras = getattr(netmiko_options, "extras", {})
        secret = extras.get("secret", "")
        # 获取用户名、密码和秘密密钥
        username = nr.inventory.defaults.username
        password = nr.inventory.defaults.password
        connection_info = {
            'device_type': 'netscaler',
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret,
        }
        commands = ['show ns version']
        output = ""
        with ConnectHandler(**connection_info) as dev_connection:
            for c in commands:
                output = output + dev_connection.send_command(c)
        HW_Version = NS_version.findall(output)
        Uptime = NS_uptime.findall(output)
        HW_Patch = NS_patch.findall(output)
        Model = NS_model.findall(output)
        device_id = Device.objects.filter(ip_address=ip)[0]  # 假设这里获取设备的id
        version_q = Version.objects.filter(dev=device_id)
        if Uptime:
            date_str = Uptime[0]
            date_obj = datetime.strptime(date_str, "%b %d %Y, %H:%M:%S")
            current_date = datetime.now()
            time_difference = current_date - date_obj
            uptime = time_difference.days
        else:
            uptime = "None"
        if version_q:
            version = version_q[0]
            version.version = HW_Version[0]
            version.patch = HW_Patch[0]
            version.series = Model[0]
            version.uptime = uptime
            version.save()
        else:
            version = Version(dev = device_id,
                              version = HW_Version[0],
                              patch = HW_Patch[0],
                              series = Model[0],
                              uptime = uptime,
                              )
            version.save()
    elif platform == 'fortinet':
        commands = ['config global', 'get system performance status', 'get system status']
        def CS(task):
            task.run(netmiko_send_config, config_commands=commands)
        CS = device.run(task=CS)
        for sw in CS.keys():
            output = CS[sw][1].result
            CS_Version = FT_version.findall(output)
            Uptime = FT_uptime.findall(output)
            Model = FT_model.findall(output)
            device_id = Device.objects.filter(ip_address=ip)[0]  # 假设这里获取设备的id
            version_q = Version.objects.filter(dev=device_id)
            CS_Patch = FT_patch.findall(output)
            
            if version_q:
                version = version_q[0]
                version.version = CS_Version[0]
                version.patch = CS_Patch[0]
                version.series = Model[0]
                version.uptime = Uptime[0]
                version.save()
            else:
                version = Version(dev=device_id,
                                  version=CS_Version[0],
                                  patch=CS_Patch[0],
                                  series=Model[0],
                                  uptime=Uptime[0],
                                  )
                version.save()
