from django.contrib import admin
from .models import Device
from import_export.admin import ImportExportModelAdmin

@admin.register(Device)

class DeviceAdmin(ImportExportModelAdmin):
    list_display = ('id', 'hostname', 'ip_address', 'platform', 'location', 'role', 'model')
