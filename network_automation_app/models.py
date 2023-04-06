from django.db import models

class Device(models.Model):
    hostname = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=255)

    PLATFORM_CHOICES = (
        ('huawei', '华为'),
        ('cisco_ios_telnet', '思科'),
        ('cisco_ios', '思科'),
        ('f5_tmsh', 'F5'),
        ('fortinet', '飞塔'),
        ('netscaler', 'NS')
    )
    platform = models.CharField(max_length=255, choices=PLATFORM_CHOICES)

    LOCATION_CHOICES = (
        ('XY', '兴议'),
        ('FD', '福地'),
        ('SQ', '石桥')
    )
    location = models.CharField(max_length=255, choices=LOCATION_CHOICES)

    Role_CHOICES = (
        ('JR', '接入交换机'),
        ('HX', '核心交换机'),
        ('HJ', '汇聚交换机'),
        ('CS', '测试环境'),
        ('CK', '出口设备'),
        ('HJ-JR', 'K8s-接入')
    )
    role = models.CharField(max_length=255, choices=Role_CHOICES)

    MODEL_CHOICES = (
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
        ('NS', 'NS')
    )
    model = models.CharField(max_length=255, choices=MODEL_CHOICES)

    def __str__(self):
        return f"{self.id}. {self.ip_address}"

class Log(models.Model):
    target = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    status = models.CharField(max_length=255)
    time = models.DateTimeField(null=True)
    messages = models.CharField(max_length=255, blank=True)
