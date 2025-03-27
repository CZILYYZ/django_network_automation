from django.contrib import admin
from django.db import models
from django.utils import timezone
import django.utils.timezone as timezone

class Device(models.Model):
    hostname = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=255)

    PLATFORM_CHOICES = (
        ('huawei', '华为'),
        ('cisco_ios_telnet', '思科'),
        ('cisco_ios', '思科'),
        ('f5_tmsh', 'F5'),
        ('fortinet', '飞塔'),
        ('netscaler', 'NS'),
        ('linux', '戴尔')
    )
    platform = models.CharField(max_length=255, choices=PLATFORM_CHOICES)

    LOCATION_CHOICES = (
        ('XY', '兴议'),
        ('FD', '福地'),
        ('XX', '西溪'),
    )
    location = models.CharField(max_length=255, choices=LOCATION_CHOICES)

    Role_CHOICES = (
        ('FW', '防火墙'),
        ('JR', '接入交换机'),
        ('HX', '核心交换机'),
        ('HJ', '汇聚交换机'),
        ('CS', '测试环境'),
        ('CK', '出口设备'),
        ('HJ-JR', 'K8s-接入'),
        ('FWQ', '服务器')
    )
    role = models.CharField(max_length=255, choices=Role_CHOICES)

    MODEL_CHOICES = (
        ('USG', 'USG'),
        ('HW5700', 'HW5700'),
        ('HWNE20', 'HWNE20'),
        ('HW8800', 'HW8800'),
        ('HW6800', 'HW6800'),
        ('HW5800', 'HW5800'),
        ('HW12800', 'HW12800'),
        ('CS45', 'CS45'),
        ('CS', 'CS'),
        ('F5', 'F5'),
        ('FT', 'FT'),
        ('NS', 'NS'),
        ('linux', 'R630')
    )
    model = models.CharField(max_length=255, choices=MODEL_CHOICES)
    created_time = models.DateTimeField('创建时间', auto_now_add=True)
    update_time = models.DateTimeField('更新时间', auto_now=True)
    def __str__(self):
        return '{}'.format(self.hostname)        

class Version(models.Model):
    dev = models.OneToOneField(verbose_name='关联设备', to='Device',on_delete=models.CASCADE)
    version = models.CharField(verbose_name='版本号', max_length=128)
    patch = models.CharField(verbose_name='补丁号', max_length=128)
    series = models.CharField(verbose_name='系列', max_length=128)
    uptime = models.CharField(verbose_name='已运行时间', max_length=128)
    created_time = models.DateTimeField(verbose_name='创建时间', auto_now_add=True)
    update_time = models.DateTimeField(verbose_name='更新时间', auto_now=True)

    
    def __str__(self):
        return '设备：{}的版本:{}'.format(self.dev, self.version)

class Log(models.Model):
    target = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    time = models.DateTimeField(null=True)
    messages = models.CharField(max_length=255, blank=True)


class Interface(models.Model):
    dev = models.ForeignKey(verbose_name='关联设备', to='Device', on_delete=models.CASCADE)
    name = models.CharField(verbose_name='端口名', max_length=128)
    phy_state = models.CharField(verbose_name='物理状态', max_length=128)
    protocol_state = models.CharField(verbose_name='协议状态', max_length=128)
    desc = models.CharField(verbose_name='端口描述', max_length=128, null=True, blank=True)
    created_time = models.DateTimeField(verbose_name='创建时间', auto_now_add=True)
    update_time = models.DateTimeField(verbose_name='更新时间', auto_now=True)

    def __str__(self):
        # 我们可以访问外键对象的属性，比如取所属设备名self.dev.name
        return '设备:{} 端口:{}'.format(self.dev, self.name)

    class Meta:
        # 唯一约束，可以添加多组，此处我们约束网络设备和端口名应全局唯一
        unique_together = [('dev', 'name')]


class ServerIp(models.Model):
    SN = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=255)
    cabinetNumber = models.CharField(max_length=255)
    JRsw = models.CharField(max_length=255)
    JRdk = models.CharField(max_length=255)
    DKms = models.CharField(max_length=255) 
    created_time = models.DateTimeField('创建时间', auto_now_add=True)
    update_time = models.DateTimeField('更新时间', auto_now=True)
    def __str__(self):
        return '{}'.format(self.ip_address)       

class ScheduledTask(models.Model):
    script_path = models.CharField(max_length=255, help_text="Path to the script to be executed.")
    cron_schedule = models.CharField(max_length=100, help_text="Cron expression defining the schedule.")
    enabled = models.BooleanField(default=True, help_text="Whether this task is enabled or not.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="The time this task was created.")
    updated_at = models.DateTimeField(auto_now=True, help_text="The last time this task was updated.")

    def __str__(self):
        return f"{self.script_path} scheduled at {self.cron_schedule}"

    class Meta:
        verbose_name = "Scheduled Task"
        verbose_name_plural = "Scheduled Tasks"
