# Generated by Django 4.1.2 on 2023-10-16 02:46

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('network_automation_app', '0004_devicedata'),
    ]

    operations = [
        migrations.DeleteModel(
            name='DeviceData',
        ),
    ]
