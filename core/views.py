import csv
import json
import io
import ipaddress
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from .models import FirewallRule, FileImport
from .forms import UploadFileForm

def rule_list(request, file_id=None):
    files = FileImport.objects.all()
    selected_file = None
    
    if file_id:
        selected_file = get_object_or_404(FileImport, id=file_id)
        rules = FirewallRule.objects.filter(file_source=selected_file)
    else:
        rules = FirewallRule.objects.all()
        
    stats = get_analysis_stats(rules)
    
    return render(request, 'list.html', {
        'rules': rules.order_by('id'),
        'files': files,
        'selected_file': selected_file,
        'stats': stats
    })

def run_analysis(request):
    if not FirewallRule.objects.exists():
        messages.error(request, "Ошибка: Отсутствует конфигурационный файл правил.")
        return redirect('rule_list')

    rules = list(FirewallRule.objects.all().order_by('id'))
    FirewallRule.objects.update(
        is_redundant=False, is_shadowed=False, is_correlated=False, recommendation=""
    )

    for i, curr in enumerate(rules):
        curr.recommendation = ""
        
        # 1. Проверка синтаксиса (Порт не нужен для ICMP и ANY)
        if curr.port is None and curr.protocol not in ['ICMP', 'ANY']:
            curr.recommendation += "Синтаксис: порт не указан (ANY). "
            curr.is_shadowed = True # Выставляем флаг, чтобы правило считалось "проблемным"

        # 2. Проверка риска (0.0.0.0/0)
        if curr.action == 'ALLOW' and curr.source_ip in ['0.0.0.0/0', 'any', '*']:
            curr.recommendation += "Риск: небезопасное разрешение (0.0.0.0/0). "
            curr.is_shadowed = True

        try:
            curr_src = ipaddress.ip_network(curr.source_ip, strict=False)
            curr_dst = ipaddress.ip_network(curr.dest_ip, strict=False)
        except ValueError:
            curr.recommendation = "Ошибка: неверный формат IP"
            curr.is_shadowed = True
            curr.save()
            continue

        # 3. Поиск конфликтов с предыдущими правилами
        for prev in rules[:i]:
            try:
                prev_src = ipaddress.ip_network(prev.source_ip, strict=False)
                prev_dst = ipaddress.ip_network(prev.dest_ip, strict=False)
            except ValueError:
                continue

            proto_match = (prev.protocol == 'ANY' or curr.protocol == 'ANY' or prev.protocol == curr.protocol)
            src_subset = curr_src.subnet_of(prev_src)
            dst_subset = curr_dst.subnet_of(prev_dst)
            port_match = (prev.port is None or prev.port == curr.port)

            if proto_match and src_subset and dst_subset and port_match:
                if prev.action == curr.action:
                    curr.is_redundant = True
                    curr.recommendation += f"Избыточность: поглощается правилом '{prev.name}' (ID:{prev.id})"
                else:
                    curr.is_shadowed = True
                    curr.recommendation += f"Затенение: правило '{prev.name}' (ID:{prev.id}) блокирует выполнение"
                break 

        if curr.is_shadowed or curr.is_redundant:
            curr.save()

    stats = get_analysis_stats(rules)
    
    messages.success(request, f"Анализ завершён. Найдено проблем: {int(stats['issues'])}")
    return redirect('rule_list')

def get_analysis_stats(rules):
    if hasattr(rules, 'filter'):
        total = rules.count()
        redundant = rules.filter(is_redundant=True).count()
        shadowed = rules.filter(is_shadowed=True).count()
        correlated = rules.filter(is_correlated=True).count()
    else:
        total = len(rules)
        redundant = sum(1 for r in rules if r.is_redundant)
        shadowed = sum(1 for r in rules if r.is_shadowed)
        correlated = sum(1 for r in rules if getattr(r, 'is_correlated', False))
    
    issues = redundant + shadowed + correlated
    return {
        'total': total,
        'redundant': redundant,
        'shadowed': shadowed,
        'correlated': correlated,
        'issues': issues,
        'issues_pct': (issues / max(total, 1)) * 100
    }

def analysis_report(request):
    rules = FirewallRule.objects.all().order_by('id')
    stats = get_analysis_stats(rules)
    issues = list(rules.filter(is_redundant=True)|rules.filter(is_shadowed=True)|rules.filter(is_correlated=True).values(
        'id', 'name', 'source_ip', 'dest_ip', 'port', 'protocol', 'action', 'recommendation'
    ))
    return JsonResponse({'stats': stats, 'issues': issues})

def upload_file(request):
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            try:
                file_import = FileImport.objects.create(filename=uploaded_file.name)
                if uploaded_file.name.endswith('.csv'):
                    handle_csv(uploaded_file, file_import)
                elif uploaded_file.name.endswith('.json'):
                    handle_json(uploaded_file, file_import)
                messages.success(request, f"Файл {uploaded_file.name} успешно импортирован")
                return redirect('rule_list')
            except Exception as e:
                messages.error(request, f"Ошибка при разборе файла: {e}")
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})

def handle_csv(file, file_import):
    decoded_file = file.read().decode('utf-8')
    io_string = io.StringIO(decoded_file)
    reader = csv.reader(io_string, delimiter=',')
    next(reader)
    
    for row in reader:
        if len(row) < 6: continue
        port_raw = row[3].strip()
        port = int(port_raw) if port_raw and port_raw.isdigit() else None
        
        FirewallRule.objects.create(
            file_source=file_import,
            name=row[0],
            source_ip=row[1],
            dest_ip=row[2],
            port=port,
            protocol=row[4].upper(),
            action=row[5].upper()
        )

def handle_json(file, file_import):
    data = json.load(file)
    for item in data:
        FirewallRule.objects.create(
            file_source=file_import,
            name=item.get('name'),
            source_ip=item.get('source_ip'),
            dest_ip=item.get('dest_ip'),
            port=item.get('port'),
            protocol=item.get('protocol', 'ANY').upper(),
            action=item.get('action', 'DENY').upper()
        )