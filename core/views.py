import csv
import json
import re
import io
import ipaddress
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from .models import FirewallRule, FileImport
from .forms import UploadFileForm
import xml.etree.ElementTree as ET
from django.db import transaction

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

    rules_queryset = FirewallRule.objects.filter(file_source=selected_file).order_by('id')
    rules = list(rules_queryset)

    if not rules:
        messages.error(request, f"В файле {selected_file.filename} нет правил.")
        return redirect('rule_list')

    rules_queryset.update(
        is_redundant=False, is_shadowed=False, is_error=False, recommendation=""
    )

    for i, curr in enumerate(rules):
        error_messages = []
        conflict_msg = ""

        try:
            curr_src = ipaddress.ip_network(curr.source_ip, strict=False)
            curr_dst = ipaddress.ip_network(curr.dest_ip, strict=False)
        except ValueError:
            curr.is_error = True
            curr.recommendation = f"Критическая ошибка: неверный формат IP ({curr.source_ip} -> {curr.dest_ip})"
            curr.save()
            continue 


        if curr.port_start < 0 or curr.port_end > 65535 or curr.port_start > curr.port_end:
            curr.is_error = True
            error_messages.append(f"Ошибка: недопустимый диапазон портов ({curr.port_start}-{curr.port_end})")

        is_src_any = curr_src.prefixlen == 0
        if curr.action == 'ALLOW' and is_src_any:
            curr.is_error = True
            error_messages.append("Критический риск: разрешен доступ ANY (0.0.0.0/0)")

        if curr.port_start == 0 and curr.port_end == 65535 and curr.protocol not in ['ICMP', 'ANY']:
            error_messages.append("Внимание: открыты все порты (ANY)")

        for prev in rules[:i]:
            try:
                prev_src = ipaddress.ip_network(prev.source_ip, strict=False)
                prev_dst = ipaddress.ip_network(prev.dest_ip, strict=False)
            except ValueError:
                continue

            proto_match = (prev.protocol == 'ANY' or curr.protocol == 'ANY' or prev.protocol == curr.protocol)

            src_subset = curr_src.subnet_of(prev_src)
            dst_subset = curr_dst.subnet_of(prev_dst)

            port_match = (curr.port_start >= prev.port_start and curr.port_end <= prev.port_end)

            if proto_match and src_subset and dst_subset and port_match:
                if prev.action == curr.action:
                    curr.is_redundant = True
                    conflict_msg = f"Избыточность: поглощается правилом '{prev.name}' (ID:{prev.id})"
                else:
                    curr.is_shadowed = True
                    conflict_msg = f"Затенение: правило '{prev.name}' (ID:{prev.id}) блокирует выполнение"
                break

        all_notes = []
        if error_messages:
            all_notes.append(" | ".join(error_messages))
        if conflict_msg:
            all_notes.append(conflict_msg)
            
        if all_notes:
            curr.recommendation = " — ".join(all_notes)
        else:
            curr.recommendation = "Конфликтов не обнаружено"

        curr.save()

    stats = get_analysis_stats(rules_queryset)
    issues_count = int(stats.get('issues', 0))
    if issues_count > 0:
        messages.warning(request, f"Анализ завершён. Найдено проблем: {issues_count}.")
    else:
        messages.success(request, "Анализ завершён. Проблем не обнаружено.")
    
    return redirect('rule_list_by_file', file_id=selected_file.id)

def get_analysis_stats(rules):
    if hasattr(rules, 'filter'):
        total = rules.count()
        redundant = rules.filter(is_redundant=True).count()
        shadowed = rules.filter(is_shadowed=True).count()
        errors = rules.filter(is_error=True).count()
    else:
        total = len(rules)
        redundant = sum(1 for r in rules if r.is_redundant)
        shadowed = sum(1 for r in rules if r.is_shadowed)
        errors = sum(1 for r in rules if getattr(r, 'is_error', False))
    
    issues = redundant + shadowed + errors
    return {
        'total': total,
        'redundant': redundant,
        'shadowed': shadowed,
        'errors': errors,
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
        Q(is_error=True)
    )
    
    issues = list(issues_queryset.values(
        'id', 'name', 'source_ip', 'dest_ip', 'port', 'protocol', 'action', 'recommendation'
    ))
    
    return JsonResponse({'stats': stats, 'issues': issues})

def upload_file(request):
    if request.method == "POST":
        files = request.FILES.getlist('file')
        vendor = request.POST.get('vendor', 'STANDARD').upper()
        s_key = get_or_create_session(request)
        
        if not files:
            messages.error(request, "Файлы не выбраны")
            return redirect('upload_file')

        success_count = 0
        last_file_id = None

        for uploaded_file in files:
            try:
                with transaction.atomic():
                    file_import = FileImport.objects.create(
                        filename=uploaded_file.name, 
                        session_id=s_key,
                        vendor=vendor
                    )
                    uploaded_file.seek(0)
                    
                    first_char = uploaded_file.read(1).decode('utf-8', errors='ignore')
                    uploaded_file.seek(0)

                    if vendor in ['USERGATE'] and first_char == '<':
                        raise ValueError(f"Файл {uploaded_file.name} похож на XML, но выбран вендор UserGate (JSON)")
                    
                    if vendor in ['CONTINENT', 'INFOTECS'] and first_char in ['{', '[']:
                        raise ValueError(f"Файл {uploaded_file.name} похож на JSON, но выбран XML-вендор")

                    try:
                        if vendor == 'CONTINENT':
                            handle_continent(uploaded_file, file_import)
                        elif vendor == 'USERGATE':
                            handle_usergate(uploaded_file, file_import)
                        elif vendor == 'INFOTECS':
                            handle_infotecs(uploaded_file, file_import)
                        else:
                            if uploaded_file.name.lower().endswith('.csv'):
                                handle_csv(uploaded_file, file_import)
                            else:
                                handle_json(uploaded_file, file_import)
                    except (json.JSONDecodeError, ET.ParseError):
                        raise ValueError(f"Формат файла не соответствует выбранному вендору {vendor}")

                    if not FirewallRule.objects.filter(file_source=file_import).exists():
                        raise ValueError(f"В файле {uploaded_file.name} не найдено правил для {vendor}")

                    last_file_id = file_import.id
                    success_count += 1

            except ValueError as ve:
                messages.error(request, str(ve))
                return redirect('upload_file') 

            except Exception as e:
                messages.error(request, f"Ошибка парсинга данных в {uploaded_file.name}: {e}")
                return redirect('rule_list')

        if success_count > 0:
            return redirect('rule_list_by_file', file_id=last_file_id)
            
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})

def handle_csv(file, file_import):
    decoded_file = file.read().decode('utf-8', errors='ignore')
    io_string = io.StringIO(decoded_file)
    reader = csv.reader(io_string, delimiter=',')
    next(reader)
    
    for row in reader:
        if len(row) < 6: continue

        port_raw = row[3].strip()
        p_min, p_max = parse_port_range(port_raw)
        
        FirewallRule.objects.create(
            file_source=file_import,
            name=row[0],
            source_ip=row[1] if '/' in row[1] else f"{row[1]}/32",
            dest_ip=row[2] if '/' in row[2] else f"{row[2]}/32",
            port_start=p_min,
            port_end=p_max,
            protocol=row[4].upper(),
            action=row[5].upper()
        )

def handle_json(file, file_import):
    data = json.load(file)
    for item in data:
        port_raw = item.get('port', 'any')
        p_min, p_max = parse_port_range(port_raw)

        FirewallRule.objects.create(
            file_source=file_import,
            name=item.get('name', 'JSON Rule'),
            source_ip=item.get('source_ip', '0.0.0.0/0'),
            dest_ip=item.get('dest_ip', '0.0.0.0/0'),
            port_start=p_min,
            port_end=p_max,
            protocol=item.get('protocol', 'ANY').upper(),
            action=item.get('action', 'DENY').upper()
        )


def handle_continent(file, file_import):
    file.seek(0)
    raw_content = file.read()
    if not raw_content:
        raise Exception("Файл пуст")
    try:
        content_str = raw_content.decode('utf-16')
    except UnicodeDecodeError:
        try:
            content_str = raw_content.decode('windows-1251')
        except UnicodeDecodeError:
            content_str = raw_content.decode('utf-8', errors='ignore')

    content_str = re.sub(r'<\?xml.*?\?>', '', content_str).strip()

    try:
        root = ET.fromstring(content_str)
        rules_found = root.findall('.//FilterRule') or root.findall('.//Rule')

        for rule in rules_found:
            name = rule.get('Description') or rule.get('Name') or "Правило Континент"
            action_raw = str(rule.get('Action') or 'deny').lower()
            action = 'ALLOW' if action_raw in ['permit', 'allow', 'pass', '1'] else 'DENY'

            def get_cidr_list(node_name):
                node = rule.find(f'.//{node_name}')
                if node is None:
                    return ['0.0.0.0/0']

                range_node = node.find('.//IPRange')
                if range_node is not None:
                    ip_from = range_node.get('From')
                    ip_to = range_node.get('To')
                    if ip_from and ip_to:
                        try:
                            start = ipaddress.IPv4Address(ip_from)
                            end = ipaddress.IPv4Address(ip_to)
                            return [str(net) for net in ipaddress.summarize_address_range(start, end)]
                        except ValueError:
                            return [ip_from + '/32']

                addr_node = node.find('.//IPAddr')
                if addr_node is not None:
                    val = addr_node.get('Value') or addr_node.text or 'any'
                    val = val.lower().strip()
                    if val in ['any', 'все', '*', '0.0.0.0', '']:
                        return ['0.0.0.0/0']
                    if '/' not in val:
                        return [f"{val}/32"]
                    return [val]

                return ['0.0.0.0/0']

            src_cidrs = get_cidr_list('Source')
            dst_cidrs = get_cidr_list('Destination')

            service_node = rule.find('.//Service')
            proto_raw = service_node.get('Protocol', 'ANY') if service_node is not None else rule.get('Protocol', 'ANY')
            port_raw = (service_node.get('Port') or service_node.get('DstPort')) if service_node is not None else rule.get('Port', '0')

            proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', 'tcp': 'TCP', 'udp': 'UDP', 'icmp': 'ICMP'}
            protocol = proto_map.get(str(proto_raw).lower(), 'ANY')
            
            p_min, p_max = parse_port_range(str(port_raw))

            for s_ip in src_cidrs:
                for d_ip in dst_cidrs:
                    FirewallRule.objects.create(
                        file_source=file_import,
                        name=name,
                        source_ip=s_ip,
                        dest_ip=d_ip,
                        port_start=p_min,
                        port_end=p_max,
                        protocol=protocol,
                        action=action,
                    )
            
    except ET.ParseError as e:
        raise Exception(f"Ошибка чтения XML структуры: {e}")
        
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

def handle_usergate(file, file_import):
    file.seek(0)
    try:
        data = json.load(file)
        rules_list = data.get('rules', data.get('items', [])) or (data if isinstance(data, list) else [])

        for item in rules_list:
            if not isinstance(item, dict) or item.get('enabled') is False:
                continue

            name = item.get('name') or item.get('description') or "UserGate Rule"
            src_ips = item.get('src_ips', ['0.0.0.0/0'])
            dst_ips = item.get('dst_ips', ['0.0.0.0/0'])
            services = item.get('services', []) or [{'proto': 'ANY', 'port': 'any'}]
            action = 'ALLOW' if str(item.get('action')).lower() in ['allow', 'pass', 'accept', 'permit'] else 'DENY'

            for s_ip in src_ips:
                for d_ip in dst_ips:
                    for svc in services:    
                        src = '0.0.0.0/0' if str(s_ip).lower() == 'any' else str(s_ip)
                        dst = '0.0.0.0/0' if str(d_ip).lower() == 'any' else str(d_ip)
                        
                        if '/' not in src and src != '0.0.0.0/0': src += '/32'
                        if '/' not in dst and dst != '0.0.0.0/0': dst += '/32'

                        p_min, p_max = parse_port_range(svc.get('port') or svc.get('dst_port'))
                        
                        proto = str(svc.get('proto', 'ANY')).upper()
                        if 'TCP' in proto: protocol = 'TCP'
                        elif 'UDP' in proto: protocol = 'UDP'
                        elif 'ICMP' in proto: protocol = 'ICMP'
                        else: protocol = proto

                        FirewallRule.objects.create(
                            file_source=file_import,
                            name=name,
                            source_ip=src,
                            dest_ip=dst,
                            port_start=p_min,
                            port_end=p_max,
                            protocol=protocol,
                            action=action
                        )
    except Exception as e:
        raise ValueError(f"Критическая ошибка парсинга UserGate: {e}")

def handle_infotecs(file, file_import):
    def clean_vipnet_ip(raw):
        if not raw: return '0.0.0.0/0'
        raw = str(raw).lower().strip()
        raw = raw.replace('[', '').replace(']', '')
        if raw in ['any', 'все', '*', '0.0.0.0', '']: 
            return '0.0.0.0/0'
        if '/' not in raw: 
            return f"{raw}/32"
        return raw
    
    file.seek(0)
    try:
        content = file.read()
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            content_str = content.decode('windows-1251', errors='ignore')
            
        root = ET.fromstring(content_str)

        rules_found = root.findall('.//FirewallRule') or root.findall('.//Rule')

        for rule in rules_found:
            name = rule.get('Name') or rule.get('name') or rule.findtext('Description') or "ViPNet Rule"

            def get_ip(node_name):
                host_node = rule.find(f'./{node_name}/Host')
                if host_node is not None and host_node.get('IP'):
                    return host_node.get('IP')

                direct_node = rule.find(f'./{node_name}')
                if direct_node is not None and direct_node.text:
                    return direct_node.text

                return rule.get(node_name.lower()) or 'any'

            src = clean_vipnet_ip(get_ip('Source'))
            dst = clean_vipnet_ip(get_ip('Destination'))

            action_raw = (rule.get('Action') or rule.get('action') or rule.findtext('Action') or 'block').lower()
            action = 'ALLOW' if action_raw in ['pass', 'permit', 'accept', 'allow'] else 'DENY'

            svc = rule.find('./Service')
            if svc is not None:
                proto_val = svc.get('Protocol') or svc.get('protocol') or 'ANY'
                port_raw = svc.get('Port') or svc.get('port') or 'any'
            else:
                proto_val = rule.findtext('Protocol') or rule.get('protocol') or 'ANY'
                port_raw = rule.findtext('Port') or rule.get('port') or 'any'

            proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', 'TCP': 'TCP', 'UDP': 'UDP', 'ICMP': 'ICMP'}
            protocol = proto_map.get(proto_val.upper(), proto_val.upper())

            p_min, p_max = parse_port_range(port_raw)

            FirewallRule.objects.create(
                file_source=file_import,
                name=name,
                source_ip=src,
                dest_ip=dst,
                port_start=p_min,
                port_end=p_max,
                protocol=protocol,
                action=action
            )
    except Exception as e:
        raise Exception(f"Ошибка парсинга: {str(e)}")

def parse_port_range(port_raw):
    p = str(port_raw).lower().strip()
    if not p or p in ['any', 'all', 'none', '*', '0', 'anyport']:
        return 0, 65535
    
    if '-' in p:
        parts = p.split('-')
        try:
            return int(parts[0]), int(parts[1])
        except:
            return 0, 65535

    if p.isdigit():
        val = int(p)
        return val, val
    
    return 0, 65535

def export_rules_csv(request, file_id=None):
    s_key = request.session.session_key
    if not s_key:
        return redirect('rule_list')

    if file_id:
        selected_file = get_object_or_404(FileImport, id=file_id, session_id=s_key)
        rules = FirewallRule.objects.filter(file_source=selected_file)
        filename = f"report_{selected_file.filename}.csv"
    else:
        rules = FirewallRule.objects.filter(file_source__session_id=s_key)
        filename = "full_analysis_report.csv"

    response = HttpResponse(content_type='text/csv')
    response.write(u'\ufeff'.encode('utf8'))
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response, delimiter=';')

    writer.writerow([
        'ID', 'Название правила', 'Исходный IP', 'Целевой IP', 
        'Протокол', 'Порт', 'Действие', 'Статус проблемы', 'Рекомендация'
    ])

    for rule in rules:
        status = "Норма"
        if rule.is_error: status = "Ошибка"
        elif rule.is_shadowed: status = "Затенение"
        elif rule.is_redundant: status = "Избыточность"
        
        if rule.port_start == 0 and rule.port_end == 65535:
            display_port = "Any"
        elif rule.port_start == rule.port_end:
            display_port = str(rule.port_start)
        else:
            display_port = f"{rule.port_start}-{rule.port_end}"

        writer.writerow([
            rule.id,
            rule.name,
            rule.source_ip,
            rule.dest_ip,
            rule.protocol,
            display_port,
            rule.action,
            status,
            rule.recommendation
        ])

    return response