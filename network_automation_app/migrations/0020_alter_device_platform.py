# Generated by Django 4.1.2 on 2024-05-27 07:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('network_automation_app', '0019_alter_device_location_alter_device_model_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='platform',
            field=models.CharField(choices=[('huawei', '华为'), ('cisco_ios_telnet', '思科'), ('cisco_ios', '思科'), ('f5_tmsh', 'F5'), ('fortinet', '飞塔'), ('netscaler', 'NS'), ('linux', '戴尔')], max_length=255),
        ),
    ]
