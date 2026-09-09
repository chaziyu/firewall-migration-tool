from fwmigrate.parsers.palo_alto import PANOSSourceParser
from pathlib import Path
import xml.etree.ElementTree as ET

FIXTURE = Path(__file__).parent / "fixtures/palo_alto/phase94_production.xml"


def phase94_xml(with_policies=False):
    root = ET.fromstring(FIXTURE.read_text())
    if with_policies:
        rules = root.find("./vsys/entry/rulebase/security/rules")
        template = rules.find("./entry")
        for index in range(2, 111):
            entry = ET.fromstring(ET.tostring(template, encoding="unicode"))
            entry.set("name", f"policy-{index}")
            rules.append(entry)
    return ET.tostring(root, encoding="unicode")

def test_pan_logging_is_source_only_and_secret_safe():
    xml = '<config><shared><log-settings><syslog><entry name="s"><server><entry name="x"><address>1.2.3.4</address><community>SECRET</community></entry></server></entry></syslog></log-settings></shared></config>'
    ir = PANOSSourceParser().extract(xml).canonical_ir
    assert ir.pan_log_server_profiles[0].migration_status == "EXTRACT_ONLY"
    assert "SECRET" not in str(ir.model_dump())

def test_pan_logging_production_hierarchy():
    xml = '<config><shared><log-settings><syslog><entry name="Syslog"><server><entry name="10.1.3.67"><server>10.1.3.67</server><transport>UDP</transport><port>514</port><format>BSD</format><address>10.1.3.67</address><facility>LOG_USER</facility></entry></server></entry></syslog><email><entry name="Email"><server><entry name="mail"><display-name>Mail</display-name><gateway>10.1.3.1</gateway><from>fw@example.com</from><to>ops@example.com</to><to>audit@example.com</to></entry></server></entry></email><snmptrap><entry name="SNMP"><version><v2c><server><entry name="mgr"><manager>10.1.3.68</manager><community>secret</community></entry></server></v2c></version></entry></snmptrap></log-settings></shared></config>'
    profiles = PANOSSourceParser().parse(xml).pan_log_server_profiles
    assert profiles[0].servers[0].address == "10.1.3.67"
    assert profiles[1].servers[0].to_addresses == ["ops@example.com", "audit@example.com"]
    assert profiles[2].servers[0].address == "10.1.3.68"
    assert profiles[2].servers[0].snmp_version == "v2c"
    assert "secret" not in str(profiles[2].model_dump())

def test_pan_logging_correlates_without_mutating_source_tokens():
    xml = '<config><shared><log-settings><syslog><entry name="S"><server><entry name="s"><address>1.1.1.1</address></entry></server></entry></syslog><profiles><entry name="F"><match-list><entry name="m"><send-syslog><member>S</member><member>Missing</member></send-syslog></entry></match-list></entry></profiles><system><match-list><entry name="system"><send-syslog><member>S</member></send-syslog></entry></match-list></system></log-settings></shared></config>'
    ir = PANOSSourceParser().parse(xml)
    match = ir.pan_log_forwarding_profiles[0].matches[0]
    assert match.syslog_profiles == ["S", "Missing"]
    assert match.resolved_syslog_profiles == ["S"]
    assert match.unresolved_syslog_profiles == ["Missing"]
    assert ir.pan_management_log_settings[0].resolved_syslog_profiles == ["S"]

def test_pan_logging_unknown_nested_child_is_unsupported():
    result = PANOSSourceParser().extract('<config><shared><log-settings><syslog><entry name="s"><future-option><value>x</value></future-option></entry></syslog></log-settings></shared></config>')
    assert any(item.status.value == "UNSUPPORTED" and "future-option" in item.source_path for item in result.inventory_items)


def test_phase94_production_counts_values_and_policy_resolution():
    result = PANOSSourceParser().extract(phase94_xml(with_policies=True))
    ir = result.canonical_ir
    assert len(ir.pan_log_server_profiles) == 6
    assert [p.profile_type for p in ir.pan_log_server_profiles] == ["syslog"] * 4 + ["email", "snmptrap"]
    assert [p.servers[0].port for p in ir.pan_log_server_profiles[:4]] == [514, 8514, 514, 8514]
    assert ir.pan_log_server_profiles[0].servers[0].address == "10.1.3.67"
    email = ir.pan_log_server_profiles[4].servers[0]
    assert (email.display_name, email.gateway, email.from_address, email.to_addresses) == ("SBG Mail", "10.1.3.1", "fw@example.com", ["ops@example.com"])
    snmp = ir.pan_log_server_profiles[5].servers[0]
    assert (snmp.snmp_version, snmp.address, snmp.community_configured) == ("v2c", "10.1.3.71", True)
    assert len(ir.pan_log_forwarding_profiles) == 4
    assert sum(len(p.matches) for p in ir.pan_log_forwarding_profiles) == 4
    assert len(ir.pan_management_log_settings) == 2
    assert len(ir.policies) == 110
    assert sum(p.source_log_setting is not None for p in ir.policies) == 110
    assert sum(p.source_log_setting_resolved for p in ir.policies) == 110
    assert ir.zones[0].source_log_setting == "LF-1"
    assert ir.zones[0].source_log_setting_resolved == "LF-1"


def test_phase94_source_accounting_has_no_normalized_phase9_objects():
    result = PANOSSourceParser().extract(phase94_xml())
    domains = {"pan_log_servers", "pan_log_forwarding_profiles", "pan_management_log_settings", "pan_dns_proxies", "pan_monitor_profiles", "pan_qos_profiles", "pan_high_availability", "pan_device_settings", "pan_vsys_settings", "pan_botnet_report", "pan_custom_reports"}
    items = [item for item in result.inventory_items if item.domain in domains]
    assert items and all(item.status.value == "EXTRACT_ONLY" for item in items)
    sections = [section for section in result.source_sections if section.path.removeprefix("palo_alto/") in domains]
    assert sections and all(section.object_count_normalized == 0 for section in sections)


def test_phase94_secret_markers_are_never_serialized():
    result = PANOSSourceParser().extract(phase94_xml())
    serialized = result.model_dump_json()
    for marker in ("PHASE9_SNMP_COMMUNITY_SECRET", "PHASE9_EMAIL_PASSWORD_SECRET", "PHASE9_SNMP_AUTH_SECRET", "PHASE9_SNMP_PRIVACY_SECRET", "PHASE9_HTTP_AUTH_SECRET"):
        assert marker not in serialized


def test_phase94_malformed_log_boolean_and_port_are_reviewed():
    xml = phase94_xml().replace("<port>514</port>", "<port>bad</port>", 1).replace("<entry name=\"system-1\">", "<entry name=\"system-1\"><send-to-panorama>maybe</send-to-panorama>")
    result = PANOSSourceParser().extract(xml)
    endpoint = result.canonical_ir.pan_log_server_profiles[0].servers[0]
    assert endpoint.port is None
    assert any("Invalid integer" in reason for reason in result.canonical_ir.pan_log_server_profiles[0].review_reasons)
    assert any("Invalid PAN yes/no" in reason for reason in result.canonical_ir.pan_management_log_settings[0].review_reasons)
