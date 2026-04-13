from django.db import models

class FileImport(models.Model):
    filename = models.CharField(
        max_length=255, 
        verbose_name="Имя файла"
    )
    import_date = models.DateTimeField(
        auto_now_add=True, 
        verbose_name="Дата загрузки"
    )

    class Meta:
        verbose_name = "Загруженный файл"
        verbose_name_plural = "Загруженные файлы"
        ordering = ['-import_date']

    def __str__(self):
        return f"{self.filename} ({self.import_date.strftime('%d.%m.%Y %H:%M')})"


class FirewallRule(models.Model):
    PROTOCOL_CHOICES = [
        ('TCP', 'TCP'),
        ('UDP', 'UDP'),
        ('ICMP', 'ICMP'),
        ('ANY', 'Any Protocol'),
    ]
    
    ACTION_CHOICES = [
        ('ALLOW', 'Allow (Разрешить)'),
        ('DENY', 'Deny (Запретить)'),
    ]
    file_source = models.ForeignKey(
        FileImport, 
        on_delete=models.CASCADE, 
        related_name='rules',
        verbose_name="Источник (файл)",
        null=True,
        blank=True
    )

    name = models.CharField(
        max_length=100, 
        verbose_name="Название правила",
        help_text="Например: 'Доступ к веб-серверу'"
    )
    source_ip = models.CharField(
        max_length=50, 
        verbose_name="Исходный IP / Маска",
        help_text="Формат: 192.168.1.0/24"
    )
    dest_ip = models.CharField(
        max_length=50, 
        verbose_name="Целевой IP / Маска",
        help_text="Формат: 10.0.0.5/32"
    )
    port = models.IntegerField(
        null=True, 
        blank=True, 
        verbose_name="Порт",
        help_text="Оставьте пустым для всех портов"
    )
    protocol = models.CharField(
        max_length=10, 
        choices=PROTOCOL_CHOICES, 
        default='ANY',
        verbose_name="Протокол"
    )
    action = models.CharField(
        max_length=10, 
        choices=ACTION_CHOICES,
        verbose_name="Действие"
    )

    is_redundant = models.BooleanField(
        default=False, 
        verbose_name="Избыточность",
        help_text="Указывает, перекрывается ли это правило другим"
    )
    is_shadowed = models.BooleanField(
        default=False, 
        verbose_name="Ошибка",
        help_text="Указывает на логический конфликт с правилом выше"
    )
    recommendation = models.TextField(
        blank=True, 
        null=True, 
        verbose_name="Рекомендация по оптимизации"
    )
    
    is_correlated = models.BooleanField(default=False, verbose_name="Корреляция")
    
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Дата добавления")

    class Meta:
        verbose_name = "Правило МСЭ"
        verbose_name_plural = "Правила МСЭ"
        ordering = ['id']

    def __str__(self):
        return f"{self.name} [{self.action}]"