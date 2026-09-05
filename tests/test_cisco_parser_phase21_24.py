from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.section_scanner import scan_cisco_asa_sections
from fwmigrate.parsers.cisco_ftd.section_scanner import scan_cisco_ftd_sections
from fwmigrate.parsers.cisco_ftd.parser import CiscoFTDParser


def test_asa_negation_is_preserved_without_inverting_unrelated_state():
    config = CiscoASAParser("no access-list OLD extended permit ip any any").parse_raw()
    assert config.access_rules == []
    assert config.unsupported_commands[0]["raw_line"].startswith("no access-list")


def test_asa_scanner_keeps_repeated_children_in_parent_range():
    sections = scan_cisco_asa_sections("interface Gi0/1\n description one\n no shutdown\naaa-server RAD protocol radius\n host 192.0.2.10\ninterface Gi0/2\n shutdown\n")
    assert sections[0].path == "interface"
    assert sections[0].line_end == 3
    assert sections[1].path == "aaa-server"
    assert sections[1].line_end == 5
    assert sections[2].path == "interface"


def test_asa_scanner_classifies_context_commands():
    paths = [section.path for section in scan_cisco_asa_sections(
        "context tenant-a\n config-url disk0:/tenant-a.cfg\n admin-context\n"
    )]
    assert paths == ["context"]


def test_asa_scanner_classifies_execution_space_context_commands():
    paths = [section.path for section in scan_cisco_asa_sections(
        "context tenant-a\nadmin-context\nallocate-interface Gi0/1\nconfig-url disk0:/tenant-a.cfg\nresource-class RC\nchangeto context tenant-a\n"
    )]
    assert paths == ["context", "admin-context", "allocate-interface", "config-url", "resource-class", "context"]


def test_asa_context_definitions_preserve_admin_url_interfaces_and_missing_url():
    config = CiscoASAParser(
        "context tenant-a\n"
        " allocate-interface Gi0/1\n"
        " config-url disk0:/tenant-a.cfg\n"
        " admin-context\n"
        " resource-class GOLD\n"
        "context tenant-b\n"
        " allocate-interface Gi0/2\n"
    ).parse_raw()
    assert [(item.name, item.config_url, item.allocated_interfaces, item.admin_context, item.resource_class) for item in config.contexts] == [
        ("tenant-a", "disk0:/tenant-a.cfg", ["Gi0/1"], True, "GOLD"),
        ("tenant-b", None, ["Gi0/2"], None, None),
    ]


def test_asa_malformed_context_command_is_parse_error_with_raw_evidence():
    config = CiscoASAParser("context tenant-a\n config-url\n").parse_raw()
    context = config.contexts[0]
    assert context.migration_status == "PARSE_ERROR"
    assert "config-url" in context.raw_lines
    assert config.diagnostics[-1].section == "context"


def test_asa_contexts_isolate_same_named_objects_and_acls():
    config = CiscoASAParser(
        "changeto context tenant-a\n"
        "object network SHARED\n host 10.0.0.1\n"
        "access-list SAME extended permit ip object SHARED any\n"
        "changeto context tenant-b\n"
        "object network SHARED\n host 10.0.1.1\n"
        "access-list SAME extended permit ip object SHARED any\n"
    ).parse_raw()
    assert [(item.name, item.source_context, item.value) for item in config.network_objects] == [
        ("SHARED", "tenant-a", "10.0.0.1"),
        ("SHARED", "tenant-b", "10.0.1.1"),
    ]
    assert [(item.acl_name, item.source_context) for item in config.access_rules] == [
        ("SAME", "tenant-a"), ("SAME", "tenant-b"),
    ]


def test_asa_context_references_do_not_cross_resolve():
    config = CiscoASAParser(
        "changeto context tenant-a\n"
        "object network ONLY_A\n host 10.0.0.1\n"
        "changeto context tenant-b\n"
        "object-group network GROUP\n network-object object ONLY_A\n"
    ).parse_raw()
    member = config.network_groups[0].member_entries[0]
    assert member.resolved is False
    assert any(
        issue["reference_type"] == "network_object"
        and issue["reference_name"] == "ONLY_A"
        and issue["source_context"] == "tenant-b"
        and not issue["resolved"]
        for issue in config.reference_issues
    )


def test_asa_context_nat_and_ir_preserve_source_context():
    parser = CiscoASAParser(
        "changeto context tenant-a\n"
        "object network REAL\n host 10.0.0.1\n nat (inside,outside) static 192.0.2.1\n"
        "changeto context tenant-b\n"
        "object network REAL\n host 10.0.1.1\n nat (inside,outside) static 192.0.2.2\n"
    )
    ir = parser.transform_to_ir()
    assert [rule.source_context for rule in parser.config.nat_rules] == ["tenant-a", "tenant-b"]
    assert [(item.name, item.source_context, item.subnet) for item in ir.addresses] == [
        ("REAL", "tenant-a", "10.0.0.1"), ("REAL", "tenant-b", "10.0.1.1"),
    ]
    assert [rule.source_context for rule in ir.nat_rules] == ["tenant-a", "tenant-b"]


def test_asa_context_source_only_vpn_and_aaa_records_are_owned():
    config = CiscoASAParser(
        "changeto context tenant-a\n"
        "ip local pool POOL_A 10.0.0.10 10.0.0.20\n"
        "aaa authentication ssh console GROUP_A\n"
        "changeto context tenant-b\n"
        "ip local pool POOL_B 10.0.1.10 10.0.1.20\n"
        "aaa authentication ssh console GROUP_B\n"
    ).parse_raw()
    assert [(item.name, item.source_context) for item in config.vpn_address_pools] == [
        ("POOL_A", "tenant-a"), ("POOL_B", "tenant-b"),
    ]
    assert {item.source_context for item in config.aaa_records} == {"tenant-a", "tenant-b"}


def test_ftd_scanner_tracks_hierarchy_and_boundaries():
    sections = scan_cisco_ftd_sections("configure network\n  ipv4 manual 192.0.2.2\nmanagement gateway 192.0.2.1\n")
    assert sections[0].line_end == 2
    assert sections[1].path == "management"


def test_ftd_negation_is_preserved_as_source_state():
    config = CiscoFTDParser("no management gateway 192.0.2.1").parse_raw()
    assert config.management_settings[0].source_attributes["negated"] is True


def test_ftd_documented_cmi_negation_keeps_final_state():
    config = CiscoFTDParser("show management-interface convergence\nno management-interface convergence").parse_raw()
    assert config.cmi_enabled is False
