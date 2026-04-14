import csv
import json
import io
import ipaddress
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db.models import Q
from django.http import JsonResponse
from .models import FirewallRule, FileImport
from .forms import UploadFileForm

def get_or_create_session(request):
    if not request.session.session_key:
        request.session.create()
    return request.session.session_key

def rule_list(request, file_id=None):
    s_key = get_or_create_session(request)
    
    files = FileImport.objects.filter(session_id=s_key)
    selected_file = None
    
    if file_id:
        selected_file = get_object_or_404(FileImport, id=file_id, session_id=s_key)
        rules = FirewallRule.objects.filter(file_source=selected_file)
    else:
        rules = FirewallRule.objects.filter(file_source__session_id=s_key)
        
    stats = get_analysis_stats(rules)
    
    return render(request, 'list.html', {
        'rules': rules.order_by('id'),
        'files': files,
        'selected_file': selected_file,
        'stats': stats
    })

def run_analysis(request, file_id=None):
    s_key = request.session.session_key
    if not s_key:
        messages.error(request, "Сессия не найдена. Загрузите файл заново.")
        return redirect('rule_list')

    if file_id:
        selected_file = get_object_or_404(FileImport, id=file_id, session_id=s_key)
    else:
        selected_file = FileImport.objects.filter(session_id=s_key).first()

    if not selected_file:
        messages.error(request, "Файлы для анализа не найдены.")
        return redirect('rule_list')

    # 3. Выбираем правила ТОЛЬКО этого файла
    rules_queryset = FirewallRule.objects.filter(file_source=selected_file).order_by('id')
    rules = list(rules_queryset)

    if not rules:
        messages.error(request, f"В файле {selected_file.filename} нет правил.")
        return redirect('rule_list')

    rules_queryset.update(
        is_redundant=False, is_shadowed=False, is_correlated=False, recommendation=""
    )

    for i, curr in enumerate(rules):
        curr.recommendation = ""

        curr.is_shadowed = False
        curr.is_redundant = False

        if curr.port is None and curr.protocol not in ['ICMP', 'ANY']:
            curr.recommendation += "Синтаксис: порт не указан (ANY). "

        if curr.action == 'ALLOW' and curr.source_ip in ['0.0.0.0/0', 'any', '*']:
            curr.recommendation += "Риск: небезопасное разрешение (0.0.0.0/0). "

        try:
            curr_src = ipaddress.ip_network(curr.source_ip, strict=False)
            curr_dst = ipaddress.ip_network(curr.dest_ip, strict=False)
        except ValueError:
            curr.recommendation = "Ошибка: неверный формат IP"
            curr.is_shadowed = True
            curr.save()
            continue
        
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

        curr.save()

    stats = get_analysis_stats(rules_queryset)
    messages.success(request, f"Анализ файла {selected_file.filename} завершён. Проблем: {int(stats['issues'])}")
    
    return redirect('rule_list_by_file', file_id=selected_file.id)

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
    s_key = request.session.session_key
    if not s_key:
        return JsonResponse({'error': 'No session'}, status=403)
        
    rules = FirewallRule.objects.filter(file_source__session_id=s_key).order_by('id')
    stats = get_analysis_stats(rules)
    
    issues_queryset = rules.filter(
        Q(is_redundant=True) | 
        Q(is_shadowed=True) | 
        Q(is_correlated=True)
    )
    
    issues = list(issues_queryset.values(
        'id', 'name', 'source_ip', 'dest_ip', 'port', 'protocol', 'action', 'recommendation'
    ))
    
    return JsonResponse({'stats': stats, 'issues': issues})

def upload_file(request):
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            s_key = get_or_create_session(request)
            uploaded_file = request.FILES['file']
            try:
                file_import = FileImport.objects.create(filename=uploaded_file.name, session_id=s_key)
                if uploaded_file.name.endswith('.csv'):
                    handle_csv(uploaded_file, file_import)
                elif uploaded_file.name.endswith('.json'):
                    handle_json(uploaded_file, file_import)
                    
                messages.success(request, f"Файл {uploaded_file.name} успешно импортирован")
                
                return redirect('rule_list_by_file', file_id=file_import.id)
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
        
def delete_file(request, file_id):
    s_key = request.session.session_key
    if not s_key:
        return redirect('rule_list')
    
    file_to_delete = get_object_or_404(FileImport, id=file_id, session_id=s_key)
    filename = file_to_delete.filename

    referer_url = request.META.get('HTTP_REFERER')
    
    file_to_delete.delete()
    messages.success(request, f"Файл {filename} удален.")

    if referer_url and f'/{file_id}/' in referer_url:
        return redirect('rule_list')
    
    return redirect(referer_url or 'rule_list')