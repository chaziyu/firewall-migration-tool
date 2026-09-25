from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

from fwmigrate.vendors.cisco_asa.export.excel import export_asa_excel

from fwmigrate.vendors.cisco_asa.web_report import build_asa_preview

from types import SimpleNamespace

from fwmigrate.vendors.cisco_asa.model import CiscoIPsecProfile, CiscoNATRule

from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLEndpoint, CiscoAccessRule

from fwmigrate.vendors.cisco_asa.model.service import CiscoPortSpec

from fwmigrate.vendors.cisco_asa.relationships.acl import build_acl_relationships

from fwmigrate.vendors.cisco_asa.relationships.identity import build_identity_relationships

from fwmigrate.vendors.cisco_asa.relationships.mpf import build_mpf_relationships

from fwmigrate.vendors.cisco_asa.relationships.nat import build_nat_relationships

from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceIndex, ASAReferenceKind

from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships

from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships

from copy import deepcopy

def test_nat_reporting_views_are_traceable_and_do_not_promote_manual_source_nat_to_vip():
    result = extract_cisco_asa_source(
        "object network WEB\n host 10.0.0.2\n nat (inside,outside) static 192.0.2.2\n"
        "object network CLIENTS\n subnet 10.1.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n"
        "object network REAL1\n host 10.2.0.1\n"
        "object network MAPPED1\n host 192.0.2.10\n"
        "object network REAL2\n host 10.2.0.10\n"
        "object network MAPPED2\n host 192.0.2.20\n"
        "object network DEST-MAPPED\n host 203.0.113.50\n"
        "object network DEST-REAL\n host 10.2.0.10\n"
        "object service REAL-SVC\n service tcp source eq 443\n"
        "object service MAPPED-SVC\n service tcp source eq 8443\n"
        "nat (inside,outside) source static REAL1 MAPPED1\n"
        "nat (inside,outside) source static REAL2 MAPPED2 destination static DEST-MAPPED DEST-REAL service REAL-SVC MAPPED-SVC\n"
        "nat (inside,outside) source dynamic any pat-pool PATPOOL\n"
    )

    pools = {row.source_rule.name: row for row in result.derived.nat.source_nat_pools}
    vips = result.derived.nat.vips

    assert len(pools) == 5
    interface_pat = next(row for row in pools.values() if row.pool_type == "interface_pat")
    assert getattr(interface_pat.mapped_interface, "name", interface_pat.mapped_interface) == "outside"
    assert any(row.pool_type == "dynamic_pat_pool" for row in pools.values())
    assert len(vips) == 2
    object_vip = next(row for row in vips if row.source_rule.owning_object == "WEB")
    twice_nat_vip = next(row for row in vips if row.source_rule.destination_mode == "static")
    assert (object_vip.real_address, object_vip.mapped_address) == ("10.0.0.2", "192.0.2.2")
    assert (twice_nat_vip.real_address, twice_nat_vip.mapped_address) == ("10.2.0.10", "203.0.113.50")
    twice_rule = twice_nat_vip.source_rule
    assert (twice_rule.service_operand_1, twice_rule.service_operand_2) == ("REAL-SVC", "MAPPED-SVC")
    assert (twice_nat_vip.real_service, twice_nat_vip.mapped_service, twice_nat_vip.protocol) == (None, None, None)
    assert all(row.source_rule.syntax_family == "object" or row.source_rule.destination_mode == "static" for row in vips)


def test_identity_nat_does_not_create_comparison_rows():
    result = extract_cisco_asa_source(
        "object network SAME\n host 10.0.0.1\n"
        "nat (inside,outside) source static SAME SAME\n"
        "nat (inside) 0 access-list NO_NAT\n"
    )
    assert not result.derived.nat.source_nat_pools
    assert not result.derived.nat.vips

def test_manual_nat_rejects_inline_address_and_object_nat_keeps_port_semantics():
    result = extract_cisco_asa_source(
        "nat (any,any) source static 10.2.0.10 192.0.2.20\n"
        "object network WEB\n host 10.0.0.2\n nat (inside,outside) static interface service tcp 80 8080\n"
    )
    manual, object_rule = result.config.nat_rules
    assert manual.extraction_status == "PARSE_ERROR"
    assert "unsupported_inline_addresses" in manual.raw_extra
    assert not result.derived.nat_relationships.rules[0].issues
    assert (object_rule.service_protocol, object_rule.original_service, object_rule.translated_service) == ("tcp", "80", "8080")

def test_twice_nat_service_consumes_two_operands_then_continues_with_options():
    result = extract_cisco_asa_source(
        "nat (inside,outside) source static REAL MAPPED service REAL-SVC MAPPED-SVC inactive "
        "route-lookup description preserve me\n"
    )
    rule = result.config.nat_rules[0]
    assert (rule.service_operand_1, rule.service_operand_2) == ("REAL-SVC", "MAPPED-SVC")
    assert rule.inactive and rule.route_lookup and rule.description == "preserve me"
    assert not rule.raw_options

def test_twice_nat_rejects_unknown_modes_without_reinterpreting_them():
    result = extract_cisco_asa_source(
        "nat (inside,outside) source dynamicx REAL MAPPED\n"
        "nat (inside,outside) source static REAL MAPPED destination dynamic MAPPED-D REAL-D\n"
    )
    source_mode, destination_mode = result.config.nat_rules
    assert source_mode.source_mode == "dynamicx" and source_mode.extraction_status == "PARSE_ERROR"
    assert destination_mode.destination_mode == "dynamic" and destination_mode.extraction_status == "PARSE_ERROR"

def test_source_nat_pools_keep_duplicate_names_separate_by_context():
    result = extract_cisco_asa_source(
        "changeto context customer-a\nobject network WEB\n host 10.0.0.1\n"
        "nat (inside,outside) source static WEB interface\n"
        "changeto context customer-b\nobject network WEB\n host 192.0.2.1\n"
        "nat (inside,outside) source static WEB interface\n"
    )
    assert [row.source_context for row in result.derived.nat.source_nat_pools] == ["customer-a", "customer-b"]
    assert [row.mapped_interface for row in result.derived.nat.source_nat_pools] == ["outside", "outside"]

def test_unresolved_nat_objects_stay_traceable_and_report_issues():
    result = extract_cisco_asa_source("nat (inside,outside) source static MISSING 192.0.2.1\n")
    row = result.derived.nat.source_nat_pools[0]
    assert row.source_rule.real_source == "MISSING"
    assert any("Unresolved" in issue for issue in row.issues)
    assert any(issue.category == "nat" and "Unresolved" in issue.message
               for issue in result.derived.transform_issues)

def test_nat_address_operand_can_resolve_to_network_group():
    rule = CiscoNATRule(name="manual-1", source_context="ctx", real_source="WEB-GROUP", mapped_source="interface")
    rule = rule.model_copy(update={"source_interface": "inside", "destination_interface": "outside"})
    config = SimpleNamespace(nat_rules=[rule])
    refs = ASAReferenceIndex()
    group = SimpleNamespace(name="WEB-GROUP")
    inside = SimpleNamespace(name="GigabitEthernet0/1")
    outside = SimpleNamespace(name="GigabitEthernet0/2")
    refs.register("ctx", ASAReferenceKind.NETWORK_GROUP, "WEB-GROUP", group)
    refs.register("ctx", ASAReferenceKind.INTERFACE, "inside", inside)
    refs.register("ctx", ASAReferenceKind.INTERFACE, "outside", outside)

    relation = build_nat_relationships(config, refs).rules[0]

    assert relation.real_source is group
    assert relation.source_interface is inside and relation.destination_interface is outside
    assert not relation.issues

def test_object_nat_order_and_source_immutability():
    result = extract_cisco_asa_source(
        "object network B\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n"
        "object network A\n host 10.0.0.2\n nat (inside,outside) static 192.0.2.2\n"
        "nat (inside,outside) source static 10.0.0.1 192.0.2.1\n")
    by_name = {row.ordering_inputs.object_name: row for row in result.derived.nat.rules if row.section == "object"}
    assert (by_name["A"].effective_order, by_name["B"].effective_order) == (2, 3)
    assert by_name["A"].translation_semantics == "static"
