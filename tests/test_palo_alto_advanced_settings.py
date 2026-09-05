from fwmigrate.parsers.palo_alto import PANOSSourceParser
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures/palo_alto/phase94_production.xml"

def test_pan_advanced_settings_preserve_explicit_values():
    xml = '<config><devices><entry name="fw"><deviceconfig><setting><session><rematch>yes</rematch><timeout-default>30</timeout-default></session><tcp><urgent-data>clear</urgent-data></tcp></setting></deviceconfig></entry></devices></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_device_operational_settings.rematch_sessions is True
    assert ir.pan_device_operational_settings.session_timeout_default_seconds == 30

def test_pan_advanced_settings_production_hierarchy():
    xml = '<config><shared><botnet><configuration><http><dynamic-dns><enabled>yes</enabled><threshold>5</threshold></dynamic-dns><malware-sites><enabled>yes</enabled><threshold>5</threshold></malware-sites><recent-domains><enabled>yes</enabled><threshold>5</threshold></recent-domains><ip-domains><enabled>yes</enabled><threshold>10</threshold></ip-domains><executables-from-unknown-sites><enabled>yes</enabled><threshold>5</threshold></executables-from-unknown-sites></http><other-applications><irc>yes</irc></other-applications><unknown-applications><unknown-tcp><sessions-per-hour>10</sessions-per-hour><destinations-per-hour>10</destinations-per-hour><session-length><minimum-bytes>50</minimum-bytes><maximum-bytes>100</maximum-bytes></session-length></unknown-tcp><unknown-udp><sessions-per-hour>10</sessions-per-hour><destinations-per-hour>10</destinations-per-hour><session-length><minimum-bytes>50</minimum-bytes><maximum-bytes>100</maximum-bytes></session-length></unknown-udp></unknown-applications></configuration><report><topn>100</topn><scheduled>yes</scheduled></report></botnet><reports><entry name="Insiden_SBG_FW"><type><thsum><sortby>count</sortby><group-by>day-of-receive_time</group-by><aggregate-by><member>count</member></aggregate-by><values><member>foo</member></values></thsum></type><topn>500</topn><topm>10</topm><caption>Insiden_SBG_FW</caption><start-time>2026-01-01</start-time><end-time>2026-01-02</end-time></entry></reports></shared></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_botnet_report_settings.dynamic_dns_threshold == 5
    assert {x.protocol for x in ir.pan_botnet_report_settings.unknown_application_thresholds} == {"tcp", "udp"}
    assert ir.pan_custom_reports[0].report_type == "thsum"
    assert ir.pan_custom_reports[0].source_attributes["values"] == ["foo"]

def test_pan_advanced_settings_unknown_nested_child_is_unsupported():
    result = PANOSSourceParser().extract('<config><shared><botnet><configuration><http><future-botnet-indicator><enabled>yes</enabled></future-botnet-indicator></http></configuration></botnet></shared></config>')
    assert any(item.status.value == "UNSUPPORTED" and "future-botnet-indicator" in item.source_path for item in result.inventory_items)


def test_phase94_advanced_settings_exact_values():
    ir = PANOSSourceParser().parse(FIXTURE.read_text())
    device = ir.pan_device_operational_settings
    assert (device.rematch_sessions, device.hostname_type_in_syslog, device.auto_acquire_commit_lock, device.wildfire_report_benign_file, device.wildfire_report_grayware_file, device.tcp_urgent_data, device.tcp_asymmetric_path, device.session_timeout_default_seconds, device.session_timeout_tcp_seconds) == (True, "FQDN", True, True, True, "clear", "bypass", 30, 600)
    assert ir.pan_vsys_settings[0].allow_forward_decrypted_content is True
    botnet = ir.pan_botnet_report_settings
    assert all(getattr(botnet, f"{name}_enabled") for name in ("dynamic_dns", "malware_sites", "recent_domains", "ip_domains", "executables_unknown_sites"))
    assert [getattr(botnet, f"{name}_threshold") for name in ("dynamic_dns", "malware_sites", "recent_domains", "ip_domains", "executables_unknown_sites")] == [11, 12, 13, 14, 15]
    assert botnet.irc_enabled and botnet.topn == 100 and botnet.scheduled
    assert [(x.protocol, x.sessions_per_hour, x.destinations_per_hour) for x in botnet.unknown_application_thresholds] == [("tcp", 10, 20), ("udp", 50, 60)]
    report = ir.pan_custom_reports[0]
    assert (report.name, report.report_type, report.sort_by, report.group_by, len(report.aggregate_by), report.topn, report.topm, report.caption, report.start_time, report.end_time) == ("Insiden_SBG_FW", "thsum", "count", "day-of-receive_time", 34, 500, 10, "Insiden_SBG_FW", "2026/09/01@00:00", "2026/09/05@23:59")


def test_phase94_malformed_botnet_values_are_reviewed():
    result = PANOSSourceParser().extract(FIXTURE.read_text().replace("<threshold>11</threshold>", "<threshold>bad</threshold>").replace("<scheduled>yes</scheduled>", "<scheduled>maybe</scheduled>"))
    botnet = result.canonical_ir.pan_botnet_report_settings
    assert botnet.dynamic_dns_threshold is None and botnet.scheduled is None
    assert botnet.review_reasons
