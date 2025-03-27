from nornir.core.filter import F
from ..models import Version, Device, Interface
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
 
def collect_interface(ip, platform):
    os.chdir(global_settings.inventory_path)
    huawei_interface = re.compile(r'(Eth-Trunk\d+) {2,}(\w{2,4}) {2,}(\w{2,4}) {2,}(.*)')
    cisco_interface = re.compile(r'(Po\d+) {2,}(\w{2,4}) {2,}(\w{2,4}) {2,}(.*)')
    nr = InitNornir(config_file="config.yaml")
    device = nr.filter(F(hostname=ip))
    if platform == 'huawei':
        def HW(task):
            task.run(netmiko_send_command, command_string='dis int des | in up')
        HW = device.run(task=HW)
        for sw in HW.keys():
            output = HW[sw][(1)].result
            split_output = output.splitlines()  # 按行分割输出
            device_id = Device.objects.filter(ip_address=ip)[0]
            interface_q = Interface.objects.filter(dev=device_id)
            if interface_q:
                # 如果已经存在接口信息，先删除原有的接口信息
                Interface.objects.filter(dev=device_id).delete()
            
            # 遍历每一行的接口信息，逐行存储到数据库中
            for line in split_output:
                HW_Interface = huawei_interface.findall(line)
                if HW_Interface:
                    interface_info = HW_Interface[0]
                    interface = Interface(dev=device_id,
                                          name=interface_info[0],
                                          phy_state=interface_info[1],
                                          protocol_state=interface_info[2],
                                          desc=interface_info[3],
                                          )
                    interface.save()
    elif platform == 'cisco_ios' or platform == 'cisco_ios_telnet':
        def HW(task):
            task.run(netmiko_send_command, command_string='show int des | in up')
        HW = device.run(task=HW)
        for sw in HW.keys():
            output = HW[sw][(1)].result
            split_output = output.splitlines()  # 按行分割输出
            device_id = Device.objects.filter(ip_address=ip)[0]
            interface_q = Interface.objects.filter(dev=device_id)
            if interface_q:
                # 如果已经存在接口信息，先删除原有的接口信息
                Interface.objects.filter(dev=device_id).delete()

            # 遍历每一行的接口信息，逐行存储到数据库中
            for line in split_output:
                HW_Interface = cisco_interface.findall(line)
                if HW_Interface:
                    interface_info = HW_Interface[0]
                    interface = Interface(dev=device_id,
                                          name=interface_info[0],
                                          phy_state=interface_info[1],
                                          protocol_state=interface_info[2],
                                          desc=interface_info[3],
                                          )
                    interface.save()
    else:
        pass
