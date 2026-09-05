import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRPANDeviceOperationalSettings, IRPANVsysSettings, IRPANBotnetReportSettings, IRPANBotnetUnknownApplicationThreshold, IRPANCustomReport
from .source_model import PANScope, pan_scope_identity
from .extraction import record_extract_only, record_parse_error
from .residual import record_unknown_children
from .xml_utils import member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.sanitize import sanitize_source_attributes

def _b(e,p,reasons=None):
    v=text_or_none(e,p)
    if v in ('yes', 'no'): return v == 'yes'
    if v is not None and reasons is not None: reasons.append(f'Invalid PAN yes/no value at {p}: {v}')
    return None
def _i(e,p,reasons=None):
    v=text_or_none(e,p)
    try:return int(v) if v is not None else None
    except (TypeError,ValueError):
        if reasons is not None: reasons.append(f'Invalid integer at {p}: {v}')
        return None

def extract_pan_advanced_settings(scope: PANScope, root: ET.Element, extraction) -> None:
    ir=extraction.canonical_ir; device=root.find('./deviceconfig')
    system = device.find('./system') if device is not None else None
    for path, domain in (('./snmp-setting', 'pan_snmp_settings'), ('./snmp', 'pan_snmp_settings'),
                         ('./telemetry', 'pan_telemetry_settings')):
        node = system.find(path) if system is not None else None
        if node is not None:
            record_extract_only(extraction, domain, f'deviceconfig/system/{path[2:]}', scope, None,
                                sanitize_source_attributes({"pan_source_entry": structured_xml_capture(node),
                                                            "pan_agent": structured_xml_capture(node.find('./agent')),
                                                            "pan_servers": [structured_xml_capture(child) for child in node.findall('./*/entry')]}),
                                notes=['PAN-OS telemetry setting retained with version-specific XML evidence.'], requires_manual_review=True)
    if device is not None:
        n=device.find('./setting')
        if n is not None:
            record_unknown_children(extraction, n, {'config', 'management', 'wildfire', 'tcp', 'session'}, scope, 'deviceconfig/setting', 'pan_device_settings', 'Unknown PAN device setting child.')
            for parent, known, path in ((n.find('./config'), {'rematch'}, 'config'), (n.find('./management'), {'hostname-type-in-syslog', 'auto-acquire-commit-lock'}, 'management'), (n.find('./wildfire'), {'report-benign-file', 'report-grayware-file'}, 'wildfire'), (n.find('./tcp'), {'urgent-data', 'asymmetric-path'}, 'tcp'), (n.find('./session'), {'rematch', 'timeout-default', 'timeout-tcp'}, 'session')):
                if parent is not None: record_unknown_children(extraction, parent, known, scope, f'deviceconfig/setting/{path}', 'pan_device_settings', 'Unknown PAN device setting field.')
            reasons=[]
            p=IRPANDeviceOperationalSettings(source_context=pan_scope_identity(scope),rematch_sessions=_b(n,'./config/rematch',reasons) if n.find('./config/rematch') is not None else _b(n,'./session/rematch',reasons),hostname_type_in_syslog=text_or_none(n,'./management/hostname-type-in-syslog'),auto_acquire_commit_lock=_b(n,'./management/auto-acquire-commit-lock',reasons),wildfire_report_benign_file=_b(n,'./wildfire/report-benign-file',reasons),wildfire_report_grayware_file=_b(n,'./wildfire/report-grayware-file',reasons),tcp_urgent_data=text_or_none(n,'./tcp/urgent-data'),tcp_asymmetric_path=text_or_none(n,'./tcp/asymmetric-path'),session_timeout_default_seconds=_i(n,'./session/timeout-default'),session_timeout_tcp_seconds=_i(n,'./session/timeout-tcp'),review_reasons=reasons,source_attributes=sanitize_source_attributes(structured_xml_capture(n)))
            ir.pan_device_operational_settings=p; record_extract_only(extraction,'pan_device_settings','deviceconfig/setting',scope,scope.name,p.source_attributes,notes=['PAN device settings are source-only.'],requires_manual_review=True)
    setting=root.find('./setting/ssl-decrypt/allow-forward-decrypted-content')
    if setting is not None:
        vsys = root.find('./setting')
        if vsys is not None:
            record_unknown_children(extraction, vsys, {'ssl-decrypt'}, scope, 'setting', 'pan_vsys_settings', 'Unknown PAN VSYS setting.')
        decrypt = root.find('./setting/ssl-decrypt')
        if decrypt is not None: record_unknown_children(extraction, decrypt, {'allow-forward-decrypted-content'}, scope, 'setting/ssl-decrypt', 'pan_vsys_settings', 'Unknown PAN SSL decrypt setting.')
        p=IRPANVsysSettings(source_context=pan_scope_identity(scope),allow_forward_decrypted_content=_b(root,'./setting/ssl-decrypt/allow-forward-decrypted-content'),source_attributes=sanitize_source_attributes(structured_xml_capture(root.find('./setting')))); ir.pan_vsys_settings.append(p); record_extract_only(extraction,'pan_vsys_settings','setting/ssl-decrypt/allow-forward-decrypted-content',scope,scope.name,p.source_attributes,notes=['PAN VSYS settings are source-only.'],requires_manual_review=True)
    botnet=root.find('./botnet')
    if botnet is None: botnet=root.find('./shared/botnet')
    e=botnet.find('./configuration') if botnet is not None else None
    report=botnet.find('./report') if botnet is not None else None
    if e is not None:
        record_unknown_children(extraction, botnet, {'configuration', 'report'}, scope, 'botnet', 'pan_botnet_report', 'Unknown PAN botnet child.')
        record_unknown_children(extraction, e, {'http', 'other-applications', 'unknown-applications'}, scope, 'botnet/configuration', 'pan_botnet_report', 'Unknown PAN botnet configuration child.')
        for parent, known, path in ((e.find('./http'), {'dynamic-dns', 'malware-sites', 'recent-domains', 'ip-domains', 'executables-from-unknown-sites'}, 'http'), (e.find('./other-applications'), {'irc'}, 'other-applications'), (e.find('./unknown-applications'), {'unknown-tcp', 'unknown-udp'}, 'unknown-applications'), (report, {'topn', 'scheduled'}, 'report')):
            if parent is not None: record_unknown_children(extraction, parent, known, scope, f'botnet/{path}', 'pan_botnet_report', 'Unknown PAN botnet nested child.')
        http = e.find('./http')
        if http is not None:
            for indicator in http:
                record_unknown_children(extraction, indicator, {'enabled', 'threshold'}, scope, f'botnet/configuration/http/{indicator.tag}', 'pan_botnet_report', 'Unknown PAN botnet indicator field.')
        reasons=[]
        p=IRPANBotnetReportSettings(dynamic_dns_enabled=_b(e,'./http/dynamic-dns/enabled',reasons),dynamic_dns_threshold=_i(e,'./http/dynamic-dns/threshold',reasons),malware_sites_enabled=_b(e,'./http/malware-sites/enabled',reasons),malware_sites_threshold=_i(e,'./http/malware-sites/threshold',reasons),recent_domains_enabled=_b(e,'./http/recent-domains/enabled',reasons),recent_domains_threshold=_i(e,'./http/recent-domains/threshold',reasons),ip_domains_enabled=_b(e,'./http/ip-domains/enabled',reasons),ip_domains_threshold=_i(e,'./http/ip-domains/threshold',reasons),executables_unknown_sites_enabled=_b(e,'./http/executables-from-unknown-sites/enabled',reasons),executables_unknown_sites_threshold=_i(e,'./http/executables-from-unknown-sites/threshold',reasons),irc_enabled=text_or_none(e,'./other-applications/irc') == 'yes',topn=_i(report,'./topn',reasons),scheduled=_b(report,'./scheduled',reasons),review_reasons=reasons,source_attributes=sanitize_source_attributes(structured_xml_capture(botnet)))
        for protocol in ('tcp','udp'):
            u=e.find(f'./unknown-applications/unknown-{protocol}')
            if u is not None:
                record_unknown_children(extraction, u, {'sessions-per-hour', 'destinations-per-hour', 'session-length'}, scope, f'botnet/configuration/unknown-applications/unknown-{protocol}', 'pan_botnet_report', 'Unknown PAN botnet application field.')
                record_unknown_children(extraction, u.find('./session-length'), {'minimum-bytes', 'maximum-bytes'}, scope, f'botnet/configuration/unknown-applications/unknown-{protocol}/session-length', 'pan_botnet_report', 'Unknown PAN botnet session field.') if u.find('./session-length') is not None else None
                p.unknown_application_thresholds.append(IRPANBotnetUnknownApplicationThreshold(protocol=protocol,sessions_per_hour=_i(u,'./sessions-per-hour'),destinations_per_hour=_i(u,'./destinations-per-hour'),minimum_bytes=_i(u,'./session-length/minimum-bytes'),maximum_bytes=_i(u,'./session-length/maximum-bytes'),source_attributes=sanitize_source_attributes(structured_xml_capture(u))))
        ir.pan_botnet_report_settings=p; record_extract_only(extraction,'pan_botnet_report','botnet/configuration',scope,scope.name,p.source_attributes,notes=['PAN Botnet report is source-only.'],requires_manual_review=True)
    for e in root.findall('.//reports/botnet-report'):
        record_unknown_children(extraction, e, {'name', 'dynamic-dns', 'malware-sites', 'recent-domains', 'ip-domains', 'executables-from-unknown-sites', 'irc', 'topn', 'scheduled'}, scope, 'reports/botnet-report', 'pan_botnet_report', 'Unknown PAN botnet report field.')
        p=IRPANBotnetReportSettings(dynamic_dns_enabled=_b(e,'./dynamic-dns/enabled'),dynamic_dns_threshold=_i(e,'./dynamic-dns/threshold'),malware_sites_enabled=_b(e,'./malware-sites/enabled'),malware_sites_threshold=_i(e,'./malware-sites/threshold'),recent_domains_enabled=_b(e,'./recent-domains/enabled'),recent_domains_threshold=_i(e,'./recent-domains/threshold'),ip_domains_enabled=_b(e,'./ip-domains/enabled'),ip_domains_threshold=_i(e,'./ip-domains/threshold'),executables_unknown_sites_enabled=_b(e,'./executables-from-unknown-sites/enabled'),executables_unknown_sites_threshold=_i(e,'./executables-from-unknown-sites/threshold'),irc_enabled=_b(e,'./irc/enabled'),topn=_i(e,'./topn'),scheduled=_b(e,'./scheduled'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))); ir.pan_botnet_report_settings=p; record_extract_only(extraction,'pan_botnet_report','reports/botnet-report',scope,e.get('name'),p.source_attributes,notes=['PAN Botnet report is source-only.'],requires_manual_review=True)
    for e in root.findall('./reports/entry')+root.findall('./shared/reports/entry')+root.findall('./reports/custom/entry')+root.findall('./reports/custom-report/entry'):
        if not e.get('name'):
            record_parse_error(extraction, 'pan_custom_reports', 'shared/reports/entry', scope, attributes=structured_xml_capture(e), notes=['PAN custom report is missing its name.'])
            continue
        typ=e.find('./type'); selected=next(iter(typ), typ) if typ is not None else None
        attrs=sanitize_source_attributes(structured_xml_capture(e)); attrs['values']=member_texts(selected,'./values/member') if selected is not None else []
        record_unknown_children(extraction, e, {'name', 'type', 'topn', 'topm', 'caption', 'start-time', 'end-time'}, scope, f'reports/entry[@name="{e.get("name")}"]', 'pan_custom_reports', 'Unknown PAN custom report field.')
        if selected is not None: record_unknown_children(extraction, selected, {'sortby', 'group-by', 'aggregate-by', 'values'}, scope, f'reports/entry[@name="{e.get("name")}"]/type/{selected.tag}', 'pan_custom_reports', 'Unknown PAN custom report type field.')
        p=IRPANCustomReport(name=e.get('name') or '<unnamed>',source_context=pan_scope_identity(scope),report_type=selected.tag if selected is not None else None,sort_by=text_or_none(selected,'./sortby') if selected is not None else text_or_none(e,'./sort-by'),group_by=text_or_none(selected,'./group-by') if selected is not None else text_or_none(e,'./group-by'),aggregate_by=member_texts(selected,'./aggregate-by/member') if selected is not None else member_texts(e,'./aggregate-by/member'),topn=_i(e,'./topn'),topm=_i(e,'./topm'),caption=text_or_none(e,'./caption'),start_time=text_or_none(e,'./start-time'),end_time=text_or_none(e,'./end-time'),source_attributes=attrs); ir.pan_custom_reports.append(p); record_extract_only(extraction,'pan_custom_reports','shared/reports/entry',scope,p.name,p.source_attributes,notes=['PAN custom report is source-only.'],requires_manual_review=True)
