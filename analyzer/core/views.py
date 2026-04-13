import csv
import json
import io
import ipaddress
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from core.models import FirewallRule, FileImport
from core.forms import UploadFileForm

def rule_list(request, file_id=None):
    files = FileImport.objects.all()
    selected_file = None
    
    if file_id:
        selected_file = get_object_or_404(FileImport, id=file_id)
        rules = FirewallRule.objects.filter(file_source=selected_file)
    else:
        rules = FirewallRule.objects.all()
    
    return render(request, 'list.html', {
        'rules': rules.order_by('id'),
        'files': files,
        'selected_file': selected_file
    })

def run_analysis(request):
    if not FirewallRule.objects.exists():
        messages.error(request, "Ошибка: Отсутствует конфигурационный файл правил.")
        return redirect('rule_list')

    rules = list(FirewallRule.objects.all().order_by('id'))
    FirewallRule.objects.update(is_redundant=False, is_shadowed=False, recommendation="")

    for i in range(len(rules)):
        current = rules[i]
        try:
            curr_src = ipaddress.ip_network(current.source_ip)
            curr_dst = ipaddress.ip_network(current.dest_ip)
        except ValueError:
            current.recommendation = "Ошибка: неверный формат IP/сети"
            current.save()
            continue

        for j in range(i):
            prev = rules[j]
            try:
                prev_src = ipaddress.ip_network(prev.source_ip)
                prev_dst = ipaddress.ip_network(prev.dest_ip)
            except ValueError:
                continue

            src_match = curr_src.subnet_of(prev_src)
            dst_match = curr_dst.subnet_of(prev_dst)
            port_match = (prev.port is None or prev.port == current.port)
            proto_match = (prev.protocol == 'ANY' or prev.protocol == current.protocol)

            if src_match and dst_match and port_match and proto_match:
                if prev.action == current.action:
                    current.is_redundant = True
                    current.recommendation = f"Избыточно: перекрывается правилом '{prev.name}' (ID: {prev.id})"
                else:
                    current.is_shadowed = True
                    current.recommendation = f"Конфликт: затеняется правилом '{prev.name}' (ID: {prev.id})"
                
                current.save()
                break

    messages.success(request, "Анализ завершен успешно!")
    return redirect('rule_list')

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
                
                messages.success(request, f"Файл {uploaded_file.name} успешно импортирован!")
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
        FirewallRule.objects.create(
            file_source=file_import,
            name=row[0],
            source_ip=row[1],
            dest_ip=row[2],
            port=int(row[3]) if row[3] and row[3].isdigit() else None,
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
            action=item.get('action').upper()
        )