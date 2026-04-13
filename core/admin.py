from django.contrib import admin
from .models import FirewallRule, FileImport

@admin.register(FileImport)
class FileImportAdmin(admin.ModelAdmin):
    list_display = ('id', 'filename', 'import_date')
    list_display_links = ('filename',)
    search_fields = ('filename',)
    readonly_fields = ('import_date',)

@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = (
        'id', 
        'name', 
        'file_source',
        'action', 
        'source_ip', 
        'dest_ip', 
        'port', 
        'protocol', 
        'is_redundant', 
        'is_shadowed'
    )
    
    list_filter = ('file_source', 'action', 'protocol', 'is_redundant', 'is_shadowed')
    
    search_fields = ('name', 'source_ip', 'dest_ip')

    fieldsets = (
        ('Метаданные', {
            'fields': ('file_source', 'name')
        }),
        ('Основная информация', {
            'fields': ('action', 'protocol', 'port')
        }),
        ('Сетевые настройки', {
            'fields': ('source_ip', 'dest_ip')
        }),
        ('Результаты анализа', {
            'fields': ('is_redundant', 'is_shadowed', 'recommendation'),
            'classes': ('collapse',),
        }),
    )

    actions = ['trigger_analysis']

    @admin.action(description="Запустить автоматизированную проверку")
    def trigger_analysis(self, request, queryset):
        from django.urls import reverse
        from django.http import HttpResponseRedirect
        return HttpResponseRedirect(reverse('run_analysis'))