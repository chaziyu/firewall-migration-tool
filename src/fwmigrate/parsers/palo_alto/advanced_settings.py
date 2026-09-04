import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRPANDeviceOperationalSettings, IRPANVsysSettings, IRPANBotnetReportSettings, IRPANBotnetUnknownApplicationThreshold, IRPANCustomReport
from .source_model import PANScope, pan_scope_identity
from .extraction import record_extract_only
from .xml_utils import member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.sanitize import sanitize_source_attributes

def _b(e,p):
    v=text_or_none(e,p); return True if v=='yes' else False if v=='no' else None
def _i(e,p):
    v=text_or_none(e,p)
    try:return int(v) if v is not None else None
    except (TypeError,ValueError):return None

def extract_pan_advanced_settings(scope: PANScope, root: ET.Element, extraction) -> None:
    ir=extraction.canonical_ir; device=root.find('./deviceconfig')
    if device is not None:
        n=device.find('./setting')
        if n is not None:
            p=IRPANDeviceOperationalSettings(source_context=pan_scope_identity(scope),rematch_sessions=_b(n,'./session/rematch'),hostname_type_in_syslog=text_or_none(n,'./management/hostname-type-in-syslog'),auto_acquire_commit_lock=_b(n,'./management/auto-acquire-commit-lock'),wildfire_report_benign_file=_b(n,'./wildfire/report-benign-file'),wildfire_report_grayware_file=_b(n,'./wildfire/report-grayware-file'),tcp_urgent_data=text_or_none(n,'./tcp/urgent-data'),tcp_asymmetric_path=text_or_none(n,'./tcp/asymmetric-path'),session_timeout_default_seconds=_i(n,'./session/timeout-default'),session_timeout_tcp_seconds=_i(n,'./session/timeout-tcp'),source_attributes=sanitize_source_attributes(structured_xml_capture(n)))
            ir.pan_device_operational_settings=p; record_extract_only(extraction,'pan_device_settings','deviceconfig/setting',scope,scope.name,p.source_attributes,notes=['PAN device settings are source-only.'],requires_manual_review=True)
    setting=root.find('./setting/ssl-decrypt/allow-forward-decrypted-content')
    if setting is not None:
        p=IRPANVsysSettings(source_context=pan_scope_identity(scope),allow_forward_decrypted_content=_b(root,'./setting/ssl-decrypt/allow-forward-decrypted-content'),source_attributes=sanitize_source_attributes(structured_xml_capture(root.find('./setting')))); ir.pan_vsys_settings.append(p); record_extract_only(extraction,'pan_vsys_settings','setting/ssl-decrypt/allow-forward-decrypted-content',scope,scope.name,p.source_attributes,notes=['PAN VSYS settings are source-only.'],requires_manual_review=True)
    for e in root.findall('.//reports/botnet-report'):
        p=IRPANBotnetReportSettings(dynamic_dns_enabled=_b(e,'./dynamic-dns/enabled'),dynamic_dns_threshold=_i(e,'./dynamic-dns/threshold'),malware_sites_enabled=_b(e,'./malware-sites/enabled'),malware_sites_threshold=_i(e,'./malware-sites/threshold'),recent_domains_enabled=_b(e,'./recent-domains/enabled'),recent_domains_threshold=_i(e,'./recent-domains/threshold'),ip_domains_enabled=_b(e,'./ip-domains/enabled'),ip_domains_threshold=_i(e,'./ip-domains/threshold'),executables_unknown_sites_enabled=_b(e,'./executables-from-unknown-sites/enabled'),executables_unknown_sites_threshold=_i(e,'./executables-from-unknown-sites/threshold'),irc_enabled=_b(e,'./irc/enabled'),topn=_i(e,'./topn'),scheduled=_b(e,'./scheduled'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))); ir.pan_botnet_report_settings=p; record_extract_only(extraction,'pan_botnet_report','reports/botnet-report',scope,e.get('name'),p.source_attributes,notes=['PAN Botnet report is source-only.'],requires_manual_review=True)
    for e in root.findall('./reports/custom/entry')+root.findall('./reports/custom-report/entry'):
        p=IRPANCustomReport(name=e.get('name') or '<unnamed>',source_context=pan_scope_identity(scope),report_type=text_or_none(e,'./type'),sort_by=text_or_none(e,'./sort-by'),group_by=text_or_none(e,'./group-by'),aggregate_by=member_texts(e,'./aggregate-by/member'),topn=_i(e,'./topn'),topm=_i(e,'./topm'),caption=text_or_none(e,'./caption'),start_time=text_or_none(e,'./start-time'),end_time=text_or_none(e,'./end-time'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))); ir.pan_custom_reports.append(p); record_extract_only(extraction,'pan_custom_reports','reports/custom/entry',scope,p.name,p.source_attributes,notes=['PAN custom report is source-only.'],requires_manual_review=True)
