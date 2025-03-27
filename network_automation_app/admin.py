from django.contrib import admin
from .models import ScheduledTask
from django.contrib import admin, messages
from .models import Device, Version, Interface, ServerIp
from import_export.admin import ImportExportModelAdmin
from .tools.update_version import collect_version
from .tools.update_interface import collect_interface
from .tools.update_Serverinfo import Synchronize_cmdb
from django.contrib.contenttypes.models import ContentType
from django.http import HttpResponseRedirect


class VersionInline(admin.TabularInline):
    # 关联的模型
    model = Version
    fields = ['series', 'version', 'patch', 'update_time']
    readonly_fields = fields
    can_delete = False
    extra = 0
    show_change_link = True
    verbose_name_plural = '版本补丁'

class InterfaceInline(admin.TabularInline):
    # 关联的模型
    model = Interface
    fields = ['name', 'protocol_state', 'phy_state', 'desc']
    readonly_fields = fields
    can_delete = False
    extra = 0
    # 单独形式的名称，对应内联管理左下角的添加按钮显示名称
    verbose_name = '端口'
    # 复数形式的名称，对应列表名称
    verbose_name_plural = '端口列表'
    show_change_link = True
    # 配置折叠的样式
    classes = ['collapse']

@admin.register(Device)
class DeviceAdmin(ImportExportModelAdmin):
    actions = ["update_version", "update_interface"]
    list_display = ('id', 'hostname', 'ip_address', 'platform', 'location', 'role', 'model',  'created_time', 'update_time')
    search_fields = ("hostname", "ip_address")
    list_filter = ("platform", "model")
    ordering = ["location", "ip_address"]
    list_display_links = ['id', 'hostname', 'ip_address']
    list_editable = ['location']
    list_per_page = 10
#    fields = ['hostname', 'ip_address', 'platform', 'location', 'role', 'model',  'created_time', 'update_time']
    readonly_fields = ['update_time', 'created_time']
    fieldsets = [
        ('基本信息',{'fields':['ip_address','hostname']}),
        ('型号信息',{'fields':['platform',('role','model')]}),
        ('位置信息',{'fields':['location']}),
        ('其他信息',{'fields':[('created_time', 'update_time')]}),
    ]
    inlines = [VersionInline,InterfaceInline]
    @admin.action(description="更新端口")
    def update_interface(modeladmin, request, queryset):
        for device in queryset:
            ip = device.ip_address
            platform = device.platform
            a = collect_interface(ip,platform)
        messages.info(request, '更新端口描述成功')

    @admin.action(description="采集版本")
    def update_version(modeladmin, request, queryset):
        for device in queryset:
            ip = device.ip_address
            platform = device.platform
            a = collect_version(ip,platform)
        messages.info(request, '更新软件版本成功')
    
                       
@admin.register(Version)
                          
class VersionAdmin(ImportExportModelAdmin):
    list_display = ['id', 'dev', 'version', 'patch', 'series', 'uptime', 'update_time']
    list_per_page = 15
    search_fields = ['dev__hostname', 'version', 'patch', 'series']
    list_display_links = ['dev']
    ordering = ['dev__hostname']
    list_filter = ['series', 'version', 'patch']
    readonly_fields = ['id', 'update_time', 'created_time']                                                                                                  


@admin.register(Interface)
class InterfaceAdmin(ImportExportModelAdmin):
    list_max_show_all = 5000
    list_display = ['id', 'dev', 'name', 'desc', 'phy_state', 'protocol_state', 'created_time']
    list_per_page = 15
    search_fields = ['dev__hostname', 'name', 'desc']
    list_display_links = ['dev', 'name']
    ordering = ['dev', 'name']
    list_filter = ['dev', 'phy_state', 'protocol_state']
    readonly_fields = ['id', 'created_time']


@admin.register(ServerIp)
class ServerIp(ImportExportModelAdmin):
    actions = ["update_Serverinfo"]
    list_max_show_all = 2000
    list_display = ['SN', 'ip_address', 'cabinetNumber', 'JRsw', 'JRdk', 'DKms', 'update_time']
    list_per_page = 20
    search_fields = ['SN', 'ip_address']
    list_display_links = ['SN']
    ordering = ['cabinetNumber', 'JRsw']
    list_filter = ['cabinetNumber']
    readonly_fields = ['update_time']
    @admin.action(description="从CMDB同步服务器信息")
    def update_Serverinfo(modeladmin, request, queryset):
        for device in queryset:
            ip = device.ip_address
            a = Synchronize_cmdb(ip)
        messages.info(request, 'CMDB同步成功')


@admin.register(ScheduledTask)
class ScheduledTaskAdmin(admin.ModelAdmin):
    list_display = ('script_path', 'cron_schedule', 'enabled', 'created_at', 'updated_at')
    list_filter = ('enabled',)
    search_fields = ('script_path', 'cron_schedule')
