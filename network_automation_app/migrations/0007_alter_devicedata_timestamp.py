# Generated by Django 4.1.2 on 2023-10-26 07:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('network_automation_app', '0006_devicedata'),
    ]

    operations = [
        migrations.AlterField(
            model_name='devicedata',
            name='timestamp',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
