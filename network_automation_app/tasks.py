from __future__ import absolute_import, unicode_literals
from nornir.core.filter import F
import netmiko
from netmiko import ConnectHandler, SCPConn
from celery import shared_task
import os, sys, pickle
import django
from django.utils import timezone
from datetime import datetime
import os, re, openpyxl, time
from django.conf import settings
from django.conf import global_settings
from nornir import InitNornir
from nornir_netmiko import netmiko_send_command, netmiko_send_config, netmiko_save_config

sys.path.append('/root/django_network_automation')
os.environ['DJANGO_SETTINGS_MODULE'] = 'django_network_automation.settings'
django.setup()
from network_automation_app.models import Device, Log


@shared_task(bind=True)
def debug_task(self):
    print('test')
 
@shared_task(bind=True)
def nornir_hosts(self):
    try:
        count = 0
        with open(global_settings.hostsyaml, 'r') as file:
            for line in file:
                if 'hostname' in line:
                    count += 1
        all_device = Device.objects.all()
        if int(len(all_device)) != int(count):
            with open(global_settings.hostsyaml, 'w+', encoding='utf-8') as file:
                for device in all_device:
                    file.write(str(device.hostname) + ':\n')
                    file.write('    ' + 'hostname:' + ' ' + device.ip_address + '\n')
                    file.write('    ' + 'platform:' + ' ' + device.platform + '\n')
                    file.write('    ' + 'data:' + '\n')
                    file.write('        ' + 'level:' + ' ' + device.role + '\n')
                    file.write('        ' + 'model:' + ' ' + device.model + '\n')
                    file.write('\n')
        else:
            pass
        log = Log(target="nornir_host更新", action="nornir_host更新", status='Success', time=timezone.now(), messages='No Error')
        log.save()
    except Exception as e:
        log = Log(target="nornir_host更新", action="nornir_host更新", status='Error', time=timezone.now(), messages=e)
        log.save()


@shared_task(bind=True)
def mac_arp(self):
    try:
        os.chdir(global_settings.inventory_path)
        nr = InitNornir(config_file="config.yaml")
        huawei_HJ = nr.filter(level='HJ', platform='huawei')
        huawei_JR = nr.filter(level='JR', platform='huawei')
        cisco_HJ = nr.filter(level='HJ', platform='cisco_ios_telnet')
        cisco_JR = nr.filter(level='JR', platform='cisco_ios')
        XY_k8s = nr.filter(level='HJ-JR', platform='huawei')
        output = huawei_HJ.run(netmiko_send_command, command_string='dis arp dynamic', read_timeout=120)
        output1 = huawei_JR.run(netmiko_send_command, command_string='dis mac-add dy', read_timeout=120)
        output2 = cisco_HJ.run(netmiko_send_command, command_string='show arp dynamic', read_timeout=120)
        output3 = cisco_JR.run(netmiko_send_command, command_string='show mac address-table dynamic', read_timeout=120)
        output4 = XY_k8s.run(netmiko_send_command, command_string='dis arp dynamic', read_timeout=120)
        output5 = XY_k8s.run(netmiko_send_command, command_string='dis mac-add dy', read_timeout=120)

        huawei_HJ_table = {}
        huawei_JR_table = {}
        cisco_HJ_table = {}
        cisco_JR_table = {}
        XY_k8s_arp_table = {}
        XY_k8s_mac_table = {}

        for a, b in [(output, huawei_HJ_table), (output1, huawei_JR_table), (output2, cisco_HJ_table),
                     (output3, cisco_JR_table), (output4, XY_k8s_arp_table), (output5, XY_k8s_mac_table)]:
            for sw in a.keys():
                b[sw] = a[sw].result

        for a, b in [(huawei_HJ_table, 'huawei_HJ_table'), (huawei_JR_table, 'huawei_JR_table'),
                     (cisco_HJ_table, 'cisco_HJ_table'), (cisco_JR_table, 'cisco_JR_table'),
                     (XY_k8s_arp_table, 'XY_k8s_arp_table'), (XY_k8s_mac_table, 'XY_k8s_mac_table')]:
            with open(
                    global_settings.arp_mac_data + b + '.pkl',
                    'wb') as f:
                pickle.dump(a, f)
        log = Log(target="arp-mac表更新", action="arp-mac表更新", status='Success', time=timezone.now(), messages='No Error')
        log.save()
    except Exception as e:
        log = Log(target="arp-mac表更新", action="arp-mac表更新", status='Error', time=timezone.now(), messages=e)
        log.save()

@shared_task(bind=True)
def backup_config(self):
    all_devices = Device.objects.all()
    os.chdir(global_settings.inventory_path)
    for dev in all_devices:
        result = []
        try:
            nr = InitNornir(config_file="config.yaml")
            device = nr.filter(hostname=dev.ip_address)
            netmiko_options = nr.inventory.defaults.connection_options.get("netmiko", {})
            extras = getattr(netmiko_options, "extras", {})
            secret = extras.get("secret", "")
            # 获取用户名、密码和秘密密钥
            username = nr.inventory.defaults.username
            password = nr.inventory.defaults.password
            connection_info = {
                'device_type': 'f5_linux',
                'ip': dev.ip_address,
                'username': username,
                'password': password,
                'secret': secret,
            }
            if dev.platform.lower() == 'huawei':
                def HW(task):
                    task.run(netmiko_send_command, command_string="dis curren")
                HW = device.run(task=HW)
                with open(f"{global_settings.network_config}{dev.hostname}.txt", "w") as f:
                    for sw in HW.keys():
                        f.write(HW[sw][1].result)
            if dev.platform.lower() == 'cisco_ios':
                def CS(task):
                    task.run(netmiko_send_command, command_string="show run")
                CS = device.run(task=CS)
                with open(f"{global_settings.network_config}{dev.hostname}.txt", "w") as f:
                    for sw in CS.keys():
                        f.write(CS[sw][1].result)
            if dev.platform.lower() == 'cisco_ios_telnet':
                def CS(task):
                    task.run(netmiko_send_command, command_string="show run")
                CS = device.run(task=CS)
                with open(f"{global_settings.network_config}{dev.hostname}.txt", "w") as f:
                    for sw in CS.keys():
                        f.write(CS[sw][1].result)
            if dev.platform.lower() == 'f5_tmsh':
                def F5(task):
                    task.run(netmiko_send_command, command_string="show running-config")
                F5 = device.run(task=F5)
                with open(f"{global_settings.network_config}{dev.hostname}.txt", "w") as f:
                    for sw in F5.keys():
                        f.write(F5[sw][1].result)
                try:
                    with ConnectHandler(**connection_info) as connect:
                        connect.send_command('rm -rf /var/local/ucs/F5-backupfile.ucs', read_timeout=120)
                        connect.send_command('tmsh save sys ucs F5-backupfile.ucs', read_timeout=120)
                    with ConnectHandler(**connection_info) as connect:
                        scp_conn = SCPConn(connect)
                        s_file = '/var/local/ucs/F5-backupfile.ucs'
                        d_file = f'{global_settings.network_config}F5-backupfile.ucs'
                        scp_conn.scp_get_file(s_file, d_file)
                        scp_conn.close()
                except (OSError, netmiko.NetmikoTimeoutException):
                    result.append("Can not connect to Device " + connection_info['ip'])
                except (EOFError, netmiko.NetMikoAuthenticationException):
                    result.append(connection_info['ip'] + " uername or passwd is wrong!")
                except (ValueError, netmiko.NetMikoAuthenticationException):
                    result.append(connection_info['ip'] + " enable passwd wrong!")
            if dev.platform.lower() == 'netscaler':
                def NS(task):
                    task.run(netmiko_send_command, command_string="show run")
                NS = device.run(task=NS)
                with open(f"{global_settings.network_config}{dev.hostname}.txt", "w") as f:
                    for sw in NS.keys():
                        f.write(NS[sw][1].result)
                try:
                    with ConnectHandler(**connection_info) as connect:
                        connect.send_command('rm system backup backupfile.tgz', read_timeout=120)
                        connect.send_command('create system backup backupfile -level full', read_timeout=120)
                    with ConnectHandler(**connection_info) as connect:
                        scp_conn = SCPConn(connect)
                        s_file = '/var/ns_sys_backup/backupfile.tgz'
                        d_file = f'{global_settings.network_config}NS-backupfile.tgz'
                        scp_conn.scp_get_file(s_file, d_file)
                        scp_conn.close()
                except (OSError, netmiko.NetmikoTimeoutException):
                    result.append("Can not connect to Device " + connection_info['ip'])
                except (EOFError, netmiko.NetMikoAuthenticationException):
                    result.append(connection_info['ip'] + " uername or passwd is wrong!")
                except (ValueError, netmiko.NetMikoAuthenticationException):
                    result.append(connection_info['ip'] + " enable passwd wrong!")
            if dev.platform.lower() == 'fortinet':
                def FT(task):
                    task.run(netmiko_send_command, command_string="show full-configuration")
                FT = device.run(task=FT)
                with open(f"{global_settings.network_config}{dev.hostname}.txt", "w") as f:
                    for sw in FT.keys():
                        f.write(FT[sw][1].result)
            log = Log(target=dev.ip_address, action='Backup Configuration', status='Success', time=timezone.now(), messages='No Error')
            log.save()
        except Exception as e:
            log = Log(target=dev.ip_address, action='Backup Configuration', status='Error', time=timezone.now(), messages=e)
            log.save()
            result.append(f'{dev.hostname}配置备份失败，请查看日志!')


@shared_task(bind=True)
def ND_cpu_memory(self):
    os.chdir(global_settings.inventory_path)
    nr = InitNornir(config_file="config.yaml")
    HW88 = nr.filter(F(platform='huawei') and F(model='HW8800'))
    HW128 = nr.filter(F(platform='huawei') and F(model='HW12800'))
    NE20 = nr.filter(F(platform='huawei') and F(model='HWNE20'))
    HW68 = nr.filter(F(model='HW5800') | F(model='HW6800'))
    HW57 = nr.filter(model='HW5700')
    CS45 = nr.filter(model='CS45')
    CS = nr.filter(model='CS')
    cmds = ['dis memory', 'dis cpu','dis clock']
    HW12800_cmds = ['dis memory', 'dis cpu','dis clock']
    NE20_cmds = ['dis memory-usage', 'dis cpu-usage','dis clock']
    HW68_cmds = ['dis cpu', 'dis memory','dis clock']
    HW57_cmds = ['dis memory', 'dis cpu','dis clock']
    CS45_cmds = ['show processes cpu', 'show processes memory','dis clock']
    CS_cmds = ['show processes cpu', 'show processes memory','dis clock']

    def HW8800(task):
        for cmd in cmds:
            task.run(netmiko_send_command, command_string=cmd)

    def HW12800(task):
        for cmd in HW12800_cmds:
            task.run(netmiko_send_command, command_string=cmd)

    def HWNE20(task):
        for cmd in NE20_cmds:
            task.run(netmiko_send_command, command_string=cmd)

    def HW6800(task):
        for cmd in HW68_cmds:
            task.run(netmiko_send_command, command_string=cmd)

    def HW5700(task):
        for cmd in HW57_cmds:
            task.run(netmiko_send_command, command_string=cmd)

    def CS4500(task):
        for cmd in CS45_cmds:
            task.run(netmiko_send_command, command_string=cmd)

    def CSJR(task):
        for cmd in CS_cmds:
            task.run(netmiko_send_command, command_string=cmd)

    HW88 = HW88.run(task=HW8800)
    HW128 = HW128.run(task=HW12800)
    HWNE20 = NE20.run(task=HWNE20)
    HW68 = HW68.run(task=HW6800)
    HW57 = HW57.run(task=HW5700)
    CS45 = CS45.run(task=CS4500)
    CS = CS.run(task=CSJR)

    memory_device = re.compile(r'Memory Using Percentage(?: Is:|:) (\d+)\S')
    memory_CS45_used = re.compile(r'(?<=System memory  : ).* (\d+)\S used,')
    memory_CS45_total = re.compile(r'(?<=System memory  : )(\d+)\S total,')
    memory_CS = re.compile(r'Processor Pool Total: +(\d+) Used: +(\d+) Free: +\d+')
    cpu_device = re.compile(r'(?:System cpu use rate is :|System CPU Using Percentage :|CPU Usage            :|CPU utilization for five seconds:) +(\d+)\S')                

    for a in (HW88, HW128, HWNE20, HW68, HW57, CS45, CS):
        for sw in a.keys():
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            device = Device.objects.get(hostname=sw)
            txt = a[sw][(1)].result + a[sw][(2)].result
            if cpu_device.search(txt):
                 cpu = cpu_device.search(txt)
                 cpu = cpu.group(1)
            else:
                 cpu = 0
            if re.search(memory_device, txt):
                memory = memory_device.search(txt)
                memory = memory.group(1)
            else:
                if memory_CS.search(txt):
                    memory_total = memory_CS.search(txt).group(1)
                    memory_used = memory_CS.search(txt).group(2)
                    memory = (float(memory_used)/float(memory_total))
                else:
                    if memory_CS45_total.search(txt) is not None and memory_CS45_used.search(txt) is not None:
                        memory_total_match = memory_CS45_total.search(txt)
                        memory_used_match = memory_CS45_used.search(txt)
                        if memory_total_match and memory_used_match:
                            memory_total = memory_total_match.group(1)
                            memory_used = memory_used_match.group(1)
                            memory = (float(memory_used) / float(memory_total))
                        else:
                            memory = 0.0
                    else:
                        memory = 0.0
            if a == HW88:
                DeviceData.objects.create(
                    device=device,
                    timestamp=timestamp,
                    cpu_usage=cpu,
                    memory_usage=memory
                )
            elif a == HW128:
                DeviceData.objects.create(
                    device=device,
                    timestamp=timestamp,
                    cpu_usage=cpu,
                    memory_usage=memory
                )
            elif a == CS45:
                DeviceData.objects.create(
                    device=device,
                    timestamp=timestamp,
                    cpu_usage=cpu,
                    memory_usage=memory
                )
            elif a == CS:
                DeviceData.objects.create(
                    device=device,
                    timestamp=timestamp,
                    cpu_usage=cpu,
                    memory_usage=memory
                )
            else:
                pass       


@shared_task
def run_script(script_path):
    subprocess.run(['python', script_path])

def schedule_task(task_id):
    task = ScheduledTask.objects.get(id=task_id)
    if task.enabled:
        cron_parts = task.cron_schedule.split()
        app.conf.beat_schedule[task.name] = {
            'task': 'myapp.tasks.run_script',
            'schedule': crontab(minute=cron_parts[0], hour=cron_parts[1], day_of_month=cron_parts[2], month_of_year=cron_parts[3], day_of_week=cron_parts[4]),
            'args': (task.script_path,)
        }
