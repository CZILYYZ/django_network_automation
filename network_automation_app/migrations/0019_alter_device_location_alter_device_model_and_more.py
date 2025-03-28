# Generated by Django 4.1.2 on 2024-05-27 07:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('network_automation_app', '0018_serverip'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='location',
            field=models.CharField(choices=[('XY', '兴议'), ('FD', '福地')], max_length=255),
        ),
        migrations.AlterField(
            model_name='device',
            name='model',
            field=models.CharField(choices=[('USG', 'USG'), ('HW5700', 'HW5700'), ('HWNE20', 'HWNE20'), ('HW8800', 'HW8800'), ('HW6800', 'HW6800'), ('HW5800', 'HW5800'), ('HW12800', 'HW12800'), ('CS45', 'CS45'), ('CS', 'CS'), ('F5', 'F5'), ('FT', 'FT'), ('NS', 'NS'), ('linux', 'R630')], max_length=255),
        ),
        migrations.AlterField(
            model_name='device',
            name='platform',
            field=models.CharField(choices=[('huawei', '华为'), ('cisco_ios_telnet', '思科'), ('cisco_ios', '思科'), ('f5_tmsh', 'F5'), ('fortinet', '飞塔'), ('netscaler', 'NS'), ('linux', '戴尔R630')], max_length=255),
        ),
        migrations.AlterField(
            model_name='device',
            name='role',
            field=models.CharField(choices=[('FW', '防火墙'), ('JR', '接入交换机'), ('HX', '核心交换机'), ('HJ', '汇聚交换机'), ('CS', '测试环境'), ('CK', '出口设备'), ('HJ-JR', 'K8s-接入'), ('FWQ', '服务器')], max_length=255),
        ),
    ]
