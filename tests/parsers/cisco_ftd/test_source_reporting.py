from io import BytesIO
from copy import deepcopy
from pathlib import Path
import json

from fwmigrate.vendors.cisco_ftd.source_report import (
    CiscoFTDSourceReporter,
    extract_cisco_ftd_source,
)
from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views
from fwmigrate.vendors.cisco_ftd.validation import validate_ftd_config
from fwmigrate.vendors.cisco_ftd.model import CiscoFTDManualNATRule, CiscoFTDAutoNATRule
from fwmigrate.vendors.cisco_ftd.derived import FTDReferenceKind


ROOT = Path(__file__).parents[2]


def _fixture(name: str) -> str:
    return (ROOT / "fixtures" / "cisco_ftd" / name).read_text(encoding="utf-8")


def test_ftd_cli_absence_and_explicit_interface_state_survive_reporting():
    source = """interface GigabitEthernet0/0
interface GigabitEthernet0/1
 management-only
 shutdown
interface GigabitEthernet0/2
 no management-only
 no shutdown
interface GigabitEthernet0/3
 ipv6 address 2001:db8::1/64
 ipv6 address 2001:db8::2/64 eui-64
 ipv6 address 2001:db8::3/64 link-local
 ipv6 address 2001:db8::4/64 eui-64 link-local
interface GigabitEthernet0/4.123
interface GigabitEthernet0/5
 vlan 124
route inside 10.0.0.0 255.255.255.0 192.0.2.1
ipv6 route inside 2001:db8::/64 2001:db8::1
ipv6 route
route
"""
    analysis = CiscoFTDSourceReporter().analyze_source(source)

    absent, affirmative, negated, ipv6, named_vlan, configured_vlan = analysis.config.interfaces
    assert (absent.management_only, absent.shutdown, absent.explicit_fields) == (None, None, [])
    assert (affirmative.management_only, affirmative.shutdown) == (True, True)
    assert {"management_only", "shutdown"} <= set(affirmative.explicit_fields)
    assert (negated.management_only, negated.shutdown) == (False, False)
    assert {"management_only", "shutdown"} <= set(negated.explicit_fields)
    assert [item.eui64 for item in ipv6.ipv6_addresses] == [None, True, None, True]
    assert [item.link_local for item in ipv6.ipv6_addresses] == [None, None, True, True]
    assert named_vlan.vlan_id is None and "vlan_id" not in named_vlan.explicit_fields
    assert named_vlan.interface_type is None and named_vlan.parent_interface is None
    assert configured_vlan.vlan_id == 124 and "vlan_id" in configured_vlan.explicit_fields
    assert [item.address_family for item in analysis.config.static_routes] == [
        "ipv4", "ipv6", "ipv6", "ipv4"]

    assert analysis.config.source_interfaces == [] and analysis.config.routes == []
    assert "no management-only" in analysis.config.interfaces[2].raw_lines
    topology = {item.name: item for item in analysis.derived.interface_topology.interfaces}
    assert topology[named_vlan.name].kind == "subinterface"
    assert topology[named_vlan.name].parent == "GigabitEthernet0/4"
    preview = CiscoFTDSourceReporter().build_preview(analysis)
    assert preview["summary"]["interfaces"] == 6

    before_export = deepcopy(analysis.config)
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(analysis, output)
    output.seek(0)
    from openpyxl import load_workbook
    workbook = load_workbook(output, read_only=True)
    assert workbook["Interfaces"].max_row == 7
    assert workbook["Routes"].max_row == 5
    assert analysis.config == before_export


def test_ftd_cli_models_do_not_supply_route_family_defaults():
    from fwmigrate.vendors.cisco_ftd.model import CiscoFTDStaticRoute

    assert CiscoFTDStaticRoute(name="malformed", raw_line="route").address_family is None


def test_ftd_cli_preserves_route_tokens_and_derives_normalized_destinations():
    source = ("interface GigabitEthernet0/1.100\n vlan 200\n"
              "route inside 10.0.0.7 255.255.255.0 192.0.2.1\n"
              "ipv6 route inside 2001:db8::1/64 2001:db8::ff\n")
    result = CiscoFTDSourceReporter().analyze_source(source)
    interface = result.config.interfaces[0]
    assert interface.parent_interface is None and interface.interface_type is None
    assert interface.vlan_id == 200
    assert result.derived.interface_topology.interfaces[0].parent == "GigabitEthernet0/1"
    ipv4, ipv6 = result.config.static_routes
    assert (ipv4.destination, ipv4.mask, ipv4.gateway) == ("10.0.0.7", "255.255.255.0", "192.0.2.1")
    assert ipv6.destination == "2001:db8::1/64"
    assert [item.normalized_destination for item in result.derived.normalized_routes] == [
        "10.0.0.0/24", "2001:db8::/64"]
    preview = CiscoFTDSourceReporter().build_preview(result)
    assert preview["normalized_routes"][0]["configured_destination"] == "10.0.0.7"
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    from openpyxl import load_workbook
    workbook = load_workbook(output, read_only=True)
    route_headers = [cell.value for cell in workbook["Routes"][1]]
    route = dict(zip(route_headers, [cell.value for cell in workbook["Routes"][2]]))
    assert (route["Destination"], route["Mask"], route["Normalized Destination"]) == (
        "10.0.0.7", "255.255.255.0", "10.0.0.0/24")
    interface_headers = [cell.value for cell in workbook["Interfaces"][1]]
    interface_row = dict(zip(interface_headers, [cell.value for cell in workbook["Interfaces"][2]]))
    assert (interface_row["Derived Kind"], interface_row["Derived Parent"], interface_row["Explicit VLAN ID"]) == (
        "subinterface", "GigabitEthernet0/1", 200)
    before = deepcopy(result.config)
    derived = build_ftd_derived_views(result.config)
    validate_ftd_config(result.config, derived)
    assert result.config == before


def test_ftd_cli_topology_and_invalid_routes_report_without_repair():
    source = ("interface GigabitEthernet0/1.100\n"
              "interface GigabitEthernet0/2\n channel-group 7 mode active\n"
              "route inside 10.0.0.7 255.0.255.0 not-an-ip\n")
    result = CiscoFTDSourceReporter().analyze_source(source)
    categories = {item.category for item in result.validation.issues}
    assert {"missing-parent", "missing-aggregate", "invalid-route"} <= categories
    route = result.config.static_routes[0]
    assert (route.destination, route.mask, route.gateway, route.raw_line) == (
        "10.0.0.7", "255.0.255.0", "not-an-ip", "route inside 10.0.0.7 255.0.255.0 not-an-ip")
    assert result.derived.normalized_routes[0].normalized_destination is None


def test_ftd_interface_topology_reports_cycles_and_resolves_aggregates():
    from fwmigrate.vendors.cisco_ftd.model import CiscoFTDConfig, CiscoFTDInterface

    config = CiscoFTDConfig(interfaces=[
        CiscoFTDInterface(name="Port-channel1"),
        CiscoFTDInterface(name="GigabitEthernet0/1", etherchannel_id=1),
        CiscoFTDInterface(name="cycle-a", parent_interface="cycle-b"),
        CiscoFTDInterface(name="cycle-b", parent_interface="cycle-a"),
    ])
    derived = build_ftd_derived_views(config)
    entries = {item.name: item for item in derived.interface_topology.interfaces}
    assert entries["GigabitEthernet0/1"].aggregate == "Port-channel1"
    assert entries["Port-channel1"].physical_interfaces == ("GigabitEthernet0/1",)
    assert any(item.category == "topology-cycle" for item in
               validate_ftd_config(config, derived).issues)


def test_fmc_source_plane_keeps_acp_and_nat_native():
    result = extract_cisco_ftd_source(_fixture("fmc_nat_pipeline_conformance.json"))

    assert result.config.source_plane == "fmc-rest-bundle"
    assert all(item.source_plane == "fmc-rest-bundle" for policy in result.config.access_control_policies for item in policy.rules)
    assert result.config.nat_policies
    policy = result.config.nat_policies[0]
    before = policy.manual_rules_before_auto[0]
    auto = policy.auto_rules[0]
    after = policy.manual_rules_after_auto[0]
    assert policy.source_id == "nat-policy"
    assert isinstance(before, CiscoFTDManualNATRule) and isinstance(auto, CiscoFTDAutoNATRule)
    assert [before.section, auto.nat_type, after.section] == ["BEFORE_AUTO", "DYNAMIC", "AFTER_AUTO"]
    assert [before.position, auto.position, after.position] == [3, 1, 4]
    assert before.original_source["id"] == "inside" and before.translated_source["id"] == "public"
    assert before.original_destination["id"] == "public" and before.translated_destination["id"] == "inside"
    assert before.original_source_port["id"] == before.translated_source_port["id"] == "http"
    assert before.original_source_service["id"] == before.translated_source_service["id"] == "http"
    assert before.original_destination_port["port"] == "80" and before.translated_destination_port["port"] == "8080"
    assert before.original_destination_service["id"] == before.translated_destination_service["id"] == "http"
    assert auto.original_network["id"] == "inside" and auto.interface_pat is True
    assert before.raw_extra["translatedDestination"]["id"] == "inside"
    assert before.source_context == "fmc:Global" and before.domain_id == "fmc-domain"
    nat_inventory = [item for item in result.inventory_items if item.source_path.endswith(("nat-policies", "nat-rules"))]
    assert [item.source_type for item in nat_inventory] == [
        "nat-policy", "manual-nat-rule", "auto-nat-rule", "manual-nat-rule"]
    assert nat_inventory[1].source_attributes["policy_id"] == policy.source_id
    assert nat_inventory[1].source_attributes["section"] == "BEFORE_AUTO"
    assert not result.derived.unresolved_references
    assert [(item["rule_kind"], item["section"]) for item in result.derived.nat_relationships] == [
        ("manual", "BEFORE_AUTO"), ("auto", None), ("manual", "AFTER_AUTO")]
    snapshot = deepcopy(policy)
    build_ftd_derived_views(result.config)
    validate_ftd_config(result.config, result.derived)
    assert policy == snapshot


def test_fdm_source_plane_is_not_fmc():
    result = extract_cisco_ftd_source(_fixture("fdm_nat_pipeline_conformance.json"))

    assert result.config.source_plane == "fdm-rest-bundle"
    assert result.config.nat_policies
    assert result.config.source_metadata["source"] == "fdm-rest-api"
    rules = result.config.nat_policies[0].rules
    source, twice = rules
    assert (source.original_source.source_id, source.translated_source.source_id) == ("inside", "public")
    assert (source.rule_type, source.sequence, source.source_translation_mode, source.service.source_id) == (
        "SOURCE", 1, "static", "http")
    assert source.observed_collection_order == 1
    assert (twice.original_source.source_id, twice.translated_source.source_id) == ("inside", "public")
    assert (twice.original_destination.source_id, twice.translated_destination.source_id) == ("public", "inside")
    assert (twice.rule_type, twice.sequence, twice.source_translation_mode, twice.destination_translation_mode) == (
        "TWICE", 2, "static", "static")
    assert twice.observed_collection_order == 2
    assert result.config.nat_policies[0].source_attributes == {
        "provenance": "FDM REST", "domain_id": "fdm-device",
        "synthetic_container": True, "source_collection": "nat_rules"}
    assert not [item for item in result.inventory_items if item.source_type == "nat-policy"]
    assert not result.derived.unresolved_references
    assert [(item["rule_kind"], item["rule_type"], item["sequence"]) for item in result.derived.nat_relationships] == [
        ("fdm", "SOURCE", 1), ("fdm", "TWICE", 2)]
    for rule in rules:
        assert {item["field"] for item in result.derived.resolved_references if item["owner"] == rule.name} >= (
            {"original_source", "translated_source", "service"} if rule is source else
            {"original_source", "translated_source", "original_destination", "translated_destination"})

    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    from openpyxl import load_workbook
    sheet = load_workbook(output, read_only=True)["NAT Rules"]
    headers = [cell.value for cell in sheet[1]]
    rows = [dict(zip(headers, row)) for row in sheet.iter_rows(min_row=2, values_only=True)]
    assert [(row["Rule Type"], row["Position"]) for row in rows] == [("SOURCE", 1), ("TWICE", 2)]
    assert (rows[0]["Original Source"], rows[0]["Translated Source"], rows[0]["FDM Service"]) == (
        "inside", "public", "http")
    assert (rows[1]["Original Source"], rows[1]["Translated Source"],
            rows[1]["Original Destination"], rows[1]["Translated Destination"]) == (
        "inside", "public", "public", "inside")
    assert (rows[0]["Source Translation Mode"], rows[1]["Destination Translation Mode"]) == ("static", "static")

    before = deepcopy(result.config)
    derived = build_ftd_derived_views(result.config)
    validate_ftd_config(result.config, derived)
    assert result.config == before

    import json
    bundle = json.loads(_fixture("fdm_nat_pipeline_conformance.json"))
    bundle["nat_rules"][0]["originalSource"] = {"id": "missing-network"}
    broken = extract_cisco_ftd_source(json.dumps(bundle))
    issue = next(item for item in broken.derived.unresolved_references if item.field == "original_source")
    assert issue.status == "UNRESOLVED"
    assert any(item.category == "unresolved-reference" for item in broken.validation.issues)

    bundle["objects"]["services"].append({"id": "missing-network", "name": "wrong-kind"})
    wrong_kind = extract_cisco_ftd_source(json.dumps(bundle))
    issue = next(item for item in wrong_kind.derived.unresolved_references if item.field == "original_source")
    assert issue.status == "WRONG_KIND" and issue.found_kinds == ("SERVICE_OBJECT",)


def test_fdm_address_service_and_group_objects_project_typed_source_fields():
    result = extract_cisco_ftd_source(_fixture("fdm_object_pipeline_conformance.json"))
    config = result.config
    addresses = {item.name: item for item in config.network_addresses}
    assert [(addresses[name].address_type, addresses[name].value) for name in ("Host", "Network", "Range")] == [
        ("Host", "192.0.2.1"), ("Network", "192.0.2.0/24"), ("Range", "192.0.2.1-192.0.2.9")]
    host = addresses["Host"]
    assert host.description == "host desc"
    assert host.override_metadata == {"overrides": [{"deviceId": "d1", "value": "192.0.2.2"}]}
    assert set(host.explicit_fields) == {"value", "description", "override_metadata"}
    assert host.raw_extra["overrides"] == host.override_metadata["overrides"]
    assert (addresses["FQDN"].address_type, addresses["FQDN"].value,
            addresses["FQDN"].fqdn_lookup_type, addresses["FQDN"].address_family) == (
        "FQDN", "example.test", "IPV4_ONLY", "ipv4")
    assert {"address_type", "value", "fqdn_lookup_type", "address_family"} <= set(addresses["FQDN"].explicit_fields)
    assert (addresses["Missing"].address_type, addresses["Missing"].value, addresses["Missing"].description,
            addresses["Missing"].fqdn_lookup_type, addresses["Missing"].address_family) == (None, None, None, None, None)

    services = {item.name: item for item in config.protocol_port_objects}
    assert (services["TCP Single"].protocol, services["TCP Single"].port, services["TCP Single"].end_port) == ("tcp", "80", None)
    assert (services["TCP Range"].port, services["TCP Range"].end_port) == ("80", "90")
    assert services["Structured Ports"].ports == [{"start": 100, "end": 110}]
    assert services["Structured Ports"].port is None and services["Structured Ports"].end_port is None
    assert (services["UDP"].protocol, services["UDP"].port) == ("udp", "53")
    assert services["Protocol Only"].protocol == "gre" and services["Protocol Only"].port is None
    assert (services["ICMP Type"].protocol, services["ICMP Type"].icmp_type, services["ICMP Type"].icmp_code) == (
        "icmp", "8", None)
    assert (services["ICMP Code"].icmp_type, services["ICMP Code"].icmp_code) == ("3", "1")
    assert set(services["TCP Single"].explicit_fields) == {"protocol", "port"}
    assert "icmp_type" not in services["TCP Single"].explicit_fields
    assert services["ICMP Code"].override_metadata == {"overrides": [{"deviceId": "d1"}]}

    network_group = config.network_groups[0]
    assert network_group.members[0].source_id == "host" and network_group.literal_members[0].value == "198.51.100.1"
    assert network_group.description == "group desc" and network_group.override_metadata == {"overrides": [{"deviceId": "d1"}]}
    port_group = config.port_object_groups[0]
    assert port_group.members[0].source_id == "tcp-single" and port_group.description == "service group desc"
    assert port_group.override_metadata == {"overrides": [{"deviceId": "d1"}]}

    before = deepcopy(config)
    derived = build_ftd_derived_views(config)
    validate_ftd_config(config, derived)
    assert config == before and not derived.unresolved_references

    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    from openpyxl import load_workbook
    workbook = load_workbook(output, read_only=True)
    address_headers = [cell.value for cell in workbook["Managed Objects"][1]]
    address_rows = [dict(zip(address_headers, row)) for row in workbook["Managed Objects"].iter_rows(min_row=2, values_only=True)]
    assert next(row for row in address_rows if row["Name"] == "Host")["Description"] == "host desc"
    service_headers = [cell.value for cell in workbook["Services"][1]]
    service_rows = [dict(zip(service_headers, row)) for row in workbook["Services"].iter_rows(min_row=2, values_only=True)]
    tcp = next(row for row in service_rows if row["Name"] == "TCP Single")
    icmp = next(row for row in service_rows if row["Name"] == "ICMP Code")
    assert (tcp["Port"], tcp["End Port"]) == ("80", None)
    assert (icmp["ICMP Type"], icmp["ICMP Code"]) == ("3", "1")


def test_cli_evidence_does_not_manufacture_managed_policy_or_nat():
    result = extract_cisco_ftd_source(
        "interface outside\n ip address 203.0.113.1 255.255.255.0\n"
    )

    assert result.config.source_plane == "ftd-text-evidence"
    assert result.config.access_control_policies == []
    assert result.config.nat_policies == []


def test_cli_sections_are_scanned_correlated_and_counted_by_source_object():
    source = """interface GigabitEthernet0/0
 nameif inside
 ip address 192.0.2.1 255.255.255.0
 description edge
route inside 10.0.0.0 255.255.255.0 192.0.2.2
configure network ipv4 manual 192.0.2.3 255.255.255.0 192.0.2.1
unsupported-command foo
"""
    result = extract_cisco_ftd_source(source)
    interface, route, management, other = result.source_sections

    assert [item.path for item in result.source_sections] == ["interfaces", "routes", "management", "other"]
    assert [item.status.value for item in result.source_sections] == ["EXTRACTED", "EXTRACTED", "PARTIAL", "UNSUPPORTED"]
    assert [(item.line_start, item.line_end) for item in result.source_sections] == [(1, 4), (5, 5), (6, 6), (7, 7)]
    assert (interface.object_count_source, interface.object_count_parsed, interface.object_count_extracted) == (1, 1, 1)
    assert (route.object_count_source, route.object_count_parsed, route.object_count_extracted) == (1, 1, 1)
    assert (management.object_count_source, management.object_count_parsed, management.object_count_extracted) == (1, 1, 0)
    assert (other.object_count_source, other.object_count_parsed, other.object_count_extracted) == (1, 0, 0)
    assert interface.parser_handler == "CiscoFTDParser.parse_raw"
    assert result.config.static_routes[0].source_attributes["source_line_number"] == 5
    assert result.config.management_settings[0].source_attributes == {
        "source_line_number": 6,
        "raw_command": "configure network ipv4 manual 192.0.2.3 255.255.255.0 192.0.2.1",
    }


def test_malformed_route_and_empty_cli_remain_visible_without_fake_sections():
    result = extract_cisco_ftd_source("route\n")
    section = result.source_sections[0]
    assert section.path == "routes"
    assert (section.line_start, section.line_end) == (1, 1)
    assert (section.object_count_source, section.object_count_parsed, section.object_count_extracted) == (1, 0, 0)
    assert section.status.value == "PARSE_ERROR"
    assert result.config.unsupported_evidence[0]["reason"] == "Malformed FTD static route"
    assert extract_cisco_ftd_source("\n!\n# comment\n: prompt\n").source_sections == []


def test_json_source_planes_do_not_run_cli_scanner_or_coverage(monkeypatch):
    from fwmigrate.vendors.cisco_ftd import source_report

    def unexpected(*args, **kwargs):
        raise AssertionError("CLI scanner or coverage classifier called for JSON source")

    monkeypatch.setattr(source_report, "scan_cisco_ftd_sections", unexpected)
    monkeypatch.setattr(source_report, "classify_cisco_ftd_coverage", unexpected)
    fmc = extract_cisco_ftd_source('{"source":"fmc-rest-api","objects":{"networks":[]}}')
    fdm = extract_cisco_ftd_source('{"format":"cisco-fdm-rest-export-v1","objects":{"networks":[]}}')
    assert fmc.source_sections[0].path == "fmc/source"
    assert fdm.source_sections[0].path == "fdm/source"


def test_unresolved_native_reference_is_reported():
    result = extract_cisco_ftd_source(
        '{"source":"fmc-rest-api","objects":{"hosts":[]},'
        '"access_policies":[{"name":"p","rules":[{"name":"r",'
        '"destinationNetworks":{"objects":[{"name":"missing"}]}}]}]}'
    )

    assert result.derived.unresolved_references
    assert result.validation.issues
    assert result.derived.unresolved_references[0].field == "destination_networks"


def test_derived_validation_does_not_mutate_ftd_source_config():
    result = extract_cisco_ftd_source(_fixture("fmc_acp_pipeline_conformance.json"))
    before = deepcopy(result.config)

    derived = build_ftd_derived_views(result.config)
    validate_ftd_config(result.config, derived)

    assert result.config == before


def test_fmc_collection_states_are_preserved_in_derived_views_and_preview():
    import json
    from fwmigrate.vendors.cisco_ftd.web_report import build_ftd_preview

    bundle = {
        "format": "cisco-fmc-rest-export-v1", "source": "fmc-rest-api",
        "objects": {"hosts": [{"id": "h1", "name": "host"}], "networks": [], "ranges": [], "securityzones": []},
        "collection": {"status": "PARTIAL", "parts": [
            {"name": "hosts", "status": "SUCCESS", "complete": True, "count": 1},
            {"name": "networks", "status": "EMPTY", "complete": True, "count": 0},
            {"name": "ranges", "status": "PARTIAL", "complete": False, "count": 1},
            {"name": "securityzones", "status": "FAILED", "complete": False, "count": 0},
            {"name": "access_rules/policy-a", "status": "SUCCESS", "complete": True, "count": 1},
            {"name": "access_rules/policy-b", "status": "FAILED", "complete": False, "count": 0},
        ]},
    }
    result = extract_cisco_ftd_source(json.dumps(bundle))
    completeness = result.derived.source_plane_completeness
    assert [completeness[f"collection:{name}"] for name in ("hosts", "networks", "ranges", "securityzones")] == [
        "present", "known-empty", "partial", "failed"]
    assert completeness["security_zones"] == "failed"
    assert completeness["acp"] == "partial"
    assert result.source_sections[0].status.value == "PARTIAL"
    assert result.inventory_items[0].status.value == "EXTRACTED"
    preview = build_ftd_preview(result)
    assert preview["summary"]["security_zones"] == 0
    assert preview["source_plane_completeness"]["collection:networks"] == "known-empty"


def test_offline_fmc_bundle_without_collection_metadata_remains_unknown():
    result = extract_cisco_ftd_source(
        '{"source":"fmc-rest-api","objects":{"networks":[]}}'
    )
    assert result.config.collection_metadata.provided is False
    assert result.source_sections[0].status.value == "UNKNOWN"
    assert result.derived.source_plane_completeness["networks"] == "unknown"
    assert result.derived.source_plane_completeness["network_objects"] == "unknown"


def test_fmc_acp_preserves_native_rule_semantics():
    result = extract_cisco_ftd_source(_fixture("fmc_acp_pipeline_conformance.json"))
    policy = result.config.access_control_policies[0]
    rule, disabled = policy.rules

    assert (rule.policy_id, rule.policy_name, rule.source_id) == ("policy-1", "Corporate ACP", "rule-1")
    assert (rule.enabled, disabled.enabled) == (True, False)
    assert (rule.position, disabled.position) == (4, 5)
    assert [item.collection_order for item in policy.rules] == [1, 2]
    assert (rule.section, rule.category, rule.action, rule.comments) == (
        "Mandatory", "Web Access", "ALLOW", "Allow managed web access"
    )
    assert rule.source_zones[0].source_id == "zone-inside"
    assert rule.destination_zones[0].source_id == "zone-outside"
    assert rule.source_networks[0].source_id == "net-inside"
    assert rule.destination_networks[0].source_id == "net-web"
    assert rule.source_ports[0].source_id == "port-source"
    assert rule.destination_ports[0].source_id == "port-destination"
    assert rule.users[0].source_id == "user-alice"
    assert rule.applications[0].source_id == "app-web"
    assert rule.urls["urlCategoriesWithReputation"][0]["reputation"] == "BENIGN_SITES"
    assert rule.url_categories[0].source_id == "url-business"
    assert rule.time_range.source_id == "time-business"
    assert rule.intrusion_policy.source_id == "ips-balanced"
    assert rule.variable_set.source_id == "variables-default"
    assert rule.file_policy.source_id == "file-inspect"
    assert (rule.log_begin, rule.log_end) == (False, True)
    assert rule.logging["sendEventsToFMC"] is False
    assert rule.source_plane == "fmc-rest-bundle"
    assert rule.domain_id == "domain-1"
    assert "applications" in rule.explicit_fields
    assert rule.raw_extra["metadata"]["ruleIndex"] == 4
    assert result.derived.acp_relationships[0]["policy_id"] == "policy-1"
    assert result.derived.acp_relationships[0]["destination_port_refs"] == rule.destination_ports
    assert not result.derived.unresolved_references


def test_fmc_acp_missing_and_explicit_empty_rules_remain_distinct():
    missing = extract_cisco_ftd_source(json.dumps({
        "format": "cisco-fmc-rest-export-v1", "source": "fmc-rest-api",
        "access_policies": [{"id": "p1", "name": "Policy"}],
    }))
    empty = extract_cisco_ftd_source(json.dumps({
        "format": "cisco-fmc-rest-export-v1", "source": "fmc-rest-api",
        "access_policies": [{"id": "p1", "name": "Policy", "rules": []}],
        "collection": {"status": "SUCCESS", "parts": [
            {"name": "access_rules/p1", "status": "EMPTY", "complete": True, "count": 0},
        ]},
    }))

    assert missing.config.access_control_policies[0].rules is None
    assert empty.config.access_control_policies[0].rules == []
    assert CiscoFTDSourceReporter().build_preview(missing)["summary"]["acp_rules"] == 0
    assert CiscoFTDSourceReporter().build_preview(empty)["summary"]["acp_rules"] == 0
    assert missing.source_sections[0].object_count_source == 1
    assert empty.source_sections[0].object_count_source == 1
    assert missing.derived.source_plane_completeness["acp"] == "unknown"
    assert empty.derived.source_plane_completeness["acp"] == "known-empty"


def test_fmc_partial_acp_counts_known_rules_and_keeps_partial_completeness():
    result = extract_cisco_ftd_source(json.dumps({
        "format": "cisco-fmc-rest-export-v1", "source": "fmc-rest-api",
        "access_policies": [
            {"id": "p1", "name": "Policy A", "rules": [{"id": "r1", "name": "Rule"}]},
            {"id": "p2", "name": "Policy B"},
        ],
    }))

    preview = CiscoFTDSourceReporter().build_preview(result)
    assert preview["summary"]["acp_rules"] == 1
    assert preview["source_plane_completeness"]["acp"] == "partial"
    assert result.source_sections[0].object_count_source == 3


def test_nullable_nat_families_survive_source_report_preview_and_excel():
    fmc = extract_cisco_ftd_source(json.dumps({
        "format": "cisco-fmc-rest-export-v1", "source": "fmc-rest-api",
        "nat_policies": [{"id": "p1", "name": "Policy", "auto_rules": []}],
        "objects": {"networkgroups": [{"id": "g1", "name": "Group"}],
                    "portobjectgroups": [{"id": "g2", "name": "Service Group"}]},
    }))
    fdm = extract_cisco_ftd_source(json.dumps({
        "format": "cisco-fdm-rest-export-v1", "objects": {},
        "nat_policies": [{"id": "p1", "name": "Policy"}],
    }))

    policy = fmc.config.nat_policies[0]
    assert policy.manual_rules_before_auto is None
    assert policy.auto_rules == []
    assert policy.manual_rules_after_auto is None
    assert policy.unclassified_manual_rules is None
    assert fdm.config.nat_policies[0].rules is None

    for result in (fmc, fdm):
        preview = CiscoFTDSourceReporter().build_preview(result)
        assert preview["summary"]["nat_rules"] == 0
        assert preview["source_plane_completeness"]["nat"] in {"unknown", "not_available_from_source_plane"}
        assert result.source_sections[0].object_count_source == (3 if result.config.source_plane == "fmc-rest-bundle" else 1)
        output = BytesIO()
        CiscoFTDSourceReporter().export_excel(result, output)
        output.seek(0)
        from openpyxl import load_workbook
        workbook = load_workbook(output, read_only=True)
        assert workbook["NAT Rules"].max_row == 1


def test_ftd_reporter_exports_source_plane_workbook():
    result = CiscoFTDSourceReporter().analyze_source(
        _fixture("fmc_acp_pipeline_conformance.json")
    )
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)

    assert output.getvalue()[:2] == b"PK"
    from openpyxl import load_workbook

    output.seek(0)
    sheet = load_workbook(output, read_only=True)["ACP Rules"]
    headers = [cell.value for cell in sheet[1]]
    row = dict(zip(headers, next(sheet.iter_rows(min_row=2, max_row=2, values_only=True))))
    assert "port-source" in row["Source Ports"]
    assert "port-destination" in row["Destination Ports"]
    assert row["Enabled"] is True and row["Log Begin"] is False


def test_fmc_device_interfaces_keep_ownership_and_resolve_zone_membership():
    import json

    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "domain": {"id": "d0", "name": "Global"},
        "objects": {
            "securityzones": [{"id": "z1", "name": "inside", "interfaces": [{"name": "GigabitEthernet0/0"}]}],
            "interfacegroups": [{"id": "g1", "name": "trusted-group"}],
        },
        "devices": [{"id": "d1", "name": "ftd-1", "resources": {"ftd_interfaces": [
            {"id": "if0", "name": "GigabitEthernet0/0", "interfaceType": "PhysicalInterface", "address": "192.0.2.1"}
        ]}}],
    }))

    interface = result.config.source_interfaces[0]
    assert (interface.name, interface.source_id, interface.device_id, interface.source_attributes["device_name"]) == (
        "GigabitEthernet0/0", "if0", "d1", "ftd-1")
    assert interface.domain_id == "d0" and interface.source_plane == "fmc-rest-bundle"
    assert interface.raw_extra["interfaceType"] == "PhysicalInterface"
    assert [zone.name for zone in result.config.security_zones] == ["inside"]
    assert [group.name for group in result.config.interface_groups] == ["trusted-group"]
    assert not result.config.device_interfaces
    assert not result.derived.unresolved_references
    inventory_interface = next(item for item in result.inventory_items if item.source_path.endswith("/interfaces"))
    assert inventory_interface.source_id == "if0" and inventory_interface.source_context == "fmc:Global"
    assert inventory_interface.source_attributes["device_id"] == "d1"
    assert inventory_interface.source_attributes["device_name"] == "ftd-1"
    assert inventory_interface.source_attributes["domain_id"] == "d0"
    assert inventory_interface.source_attributes["source_plane"] == "fmc-rest-bundle"

    before = deepcopy(result.config)
    validate_ftd_config(result.config, build_ftd_derived_views(result.config))
    assert result.config == before


def test_zone_name_reference_stays_ambiguous_across_devices():
    import json

    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "objects": {"securityzones": [{"id": "z1", "name": "inside", "interfaces": ["GigabitEthernet0/0"]}]},
        "devices": [{"id": device_id, "name": device_id, "resources": {"ftd_interfaces": [
            {"id": f"{device_id}-if0", "name": "GigabitEthernet0/0"}
        ]}} for device_id in ("d1", "d2")],
    }))

    issue = next(item for item in result.derived.unresolved_references if item.field == "interfaces")
    assert issue.status == "AMBIGUOUS"
    assert any(item.category == "ambiguous-reference" for item in result.validation.issues)


def _reference_result(objects, reference, domain_id="domain-a"):
    import json
    return extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api", "domain": {"id": domain_id, "name": domain_id},
        "objects": objects,
        "access_policies": [{"id": "p", "name": "policy", "rules": [{"id": "r", "name": "rule",
            "destinationNetworks": {"objects": [reference]}}]}],
    }))


def test_ftd_reference_resolution_is_typed_and_domain_scoped():
    result = _reference_result({
        "hosts": [{"id": "host-1", "name": "shared"}],
        "protocolportobjects": [{"id": "service-1", "name": "shared"}],
    }, {"name": "shared"})

    resolved = result.derived.resolved_references
    assert [(item["kind"], item["target_id"]) for item in resolved if item["field"] == "destination_networks"] == [
        (FTDReferenceKind.NETWORK_ADDRESS.value, "host-1")]
    assert not [item for item in result.derived.unresolved_references if item.field == "destination_networks"]

    wrong_kind = _reference_result({"protocolportobjects": [{"id": "service-1", "name": "shared"}]}, {"name": "shared"})
    issue = next(item for item in wrong_kind.derived.unresolved_references if item.field == "destination_networks")
    assert issue.status == "WRONG_KIND" and issue.reason == "wrong-kind"
    assert issue.expected_kinds == (FTDReferenceKind.NETWORK_ADDRESS.value, FTDReferenceKind.NETWORK_GROUP.value)
    assert any(item.category == "wrong-kind-reference" for item in wrong_kind.validation.issues)


def test_ftd_reference_id_precedes_name_and_domains_do_not_collide():
    result = _reference_result({"hosts": [
        {"id": "host-a", "name": "server"}, {"id": "host-b", "name": "server"},
    ]}, {"id": "host-b", "name": "server"})
    match = next(item for item in result.derived.resolved_references if item["field"] == "destination_networks")
    assert match["target_id"] == "host-b"

    result = _reference_result({"hosts": [{"id": "host-a", "name": "server"}]}, {"name": "server"})
    other_domain = _reference_result({"hosts": [{"id": "host-b", "name": "server"}]}, {"name": "server"}, "domain-b")
    result.config.network_addresses.extend(other_domain.config.network_addresses)
    derived = build_ftd_derived_views(result.config)
    match = next(item for item in derived.resolved_references if item["field"] == "destination_networks")
    assert match["target_id"] == "host-a"


def test_ftd_same_kind_duplicate_name_is_ambiguous():
    result = _reference_result({"hosts": [
        {"id": "host-a", "name": "shared"}, {"id": "host-b", "name": "shared"},
    ]}, {"name": "shared"})
    issue = next(item for item in result.derived.unresolved_references if item.field == "destination_networks")
    assert issue.status == "AMBIGUOUS" and issue.reason == "ambiguous"


def test_fmc_address_service_and_group_objects_project_typed_source_fields():
    import json

    bundle = {
        "format": "cisco-fmc-rest-export-v1", "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {
            "networkaddresses": [
                {"id": "host", "name": "Host", "type": "Host", "value": "192.0.2.1", "description": "host desc", "overrides": [{"device": {"id": "d1"}, "value": "192.0.2.2"}]},
                {"id": "network", "name": "Network", "type": "Network", "value": "192.0.2.0/24"},
                {"id": "range", "name": "Range", "type": "Range", "value": "192.0.2.1-192.0.2.9"},
                {"id": "fqdn", "name": "FQDN", "type": "FQDN", "value": "example.test", "lookupType": "IPV4_ONLY", "addressFamily": "ipv4"},
                {"id": "missing", "name": "Missing", "type": "Host"},
            ],
            "networkgroups": [{"id": "ng", "name": "Network Group", "description": "group desc",
                "objects": [{"id": "host", "name": "Host", "type": "Host"}],
                "literals": [{"value": "198.51.100.1", "type": "Host"}], "overrides": [{"deviceId": "d1"}]}],
            "protocolportobjects": [
                {"id": "http", "name": "HTTP", "protocol": "6", "port": "80", "description": "web"},
                {"id": "range-port", "name": "Range", "protocol": "6", "port": "80", "endPort": "90"},
                {"id": "udp", "name": "UDP", "protocol": "17"},
                {"id": "protocol", "name": "Protocol", "protocol": "47"},
                {"id": "icmp", "name": "ICMP", "protocol": "1", "icmpType": "8"},
                {"id": "icmp-code", "name": "ICMP Code", "protocol": "1", "icmpType": "3", "icmpCode": "1", "overrides": [{"deviceId": "d1"}]},
            ],
            "portobjectgroups": [{"id": "pg", "name": "Port Group", "description": "ports",
                "objects": [{"id": "http", "name": "HTTP", "type": "ProtocolPortObject"}], "overrides": [{"deviceId": "d1"}]}],
        },
        "access_policies": [{"id": "p", "name": "Policy", "rules": [{"id": "r", "name": "Rule",
            "destinationNetworks": {"objects": [{"id": "host", "name": "Host", "type": "Host"}]},
            "destinationPorts": {"objects": [{"id": "http", "name": "HTTP", "type": "ProtocolPortObject"}]}}]}],
    }
    result = extract_cisco_ftd_source(json.dumps(bundle))
    config = result.config
    addresses = {item.name: item for item in config.network_addresses}
    assert [(addresses[key].address_type, addresses[key].value) for key in ("Host", "Network", "Range", "FQDN")] == [
        ("Host", "192.0.2.1"), ("Network", "192.0.2.0/24"), ("Range", "192.0.2.1-192.0.2.9"), ("FQDN", "example.test")]
    host = addresses["Host"]
    assert (host.source_id, host.description, host.domain_id) == ("host", "host desc", "domain-1")
    assert host.override_metadata == {"overrides": [{"device": {"id": "d1"}, "value": "192.0.2.2"}]}
    assert {"address_type", "value", "description", "override_metadata"} <= set(host.explicit_fields)
    assert host.raw_extra["overrides"] == host.override_metadata["overrides"]
    assert addresses["FQDN"].fqdn_lookup_type == "IPV4_ONLY" and addresses["FQDN"].address_family == "ipv4"
    assert addresses["Missing"].value is None and addresses["Missing"].description is None
    assert "value" not in addresses["Missing"].explicit_fields

    services = {item.name: item for item in config.protocol_port_objects}
    assert (services["HTTP"].protocol, services["HTTP"].port) == ("6", "80")
    assert (services["Range"].port, services["Range"].end_port) == ("80", "90")
    assert services["UDP"].protocol == "17" and services["UDP"].port is None
    assert services["Protocol"].protocol == "47" and services["Protocol"].port is None
    assert (services["ICMP"].protocol, services["ICMP"].icmp_type, services["ICMP"].icmp_code) == ("1", "8", None)
    assert (services["ICMP Code"].icmp_type, services["ICMP Code"].icmp_code) == ("3", "1")
    assert services["HTTP"].description == "web"
    assert "port" in services["HTTP"].explicit_fields and "icmp_type" not in services["HTTP"].explicit_fields
    assert services["ICMP Code"].override_metadata == {"overrides": [{"deviceId": "d1"}]}

    network_group = config.network_groups[0]
    assert network_group.description == "group desc" and network_group.members[0].source_id == "host"
    assert network_group.literal_members[0].value == "198.51.100.1"
    assert network_group.override_metadata == {"overrides": [{"deviceId": "d1"}]}
    port_group = config.port_object_groups[0]
    assert port_group.description == "ports" and port_group.members[0].source_id == "http"
    assert port_group.override_metadata == {"overrides": [{"deviceId": "d1"}]}

    before = deepcopy(config)
    derived = build_ftd_derived_views(config)
    validate_ftd_config(config, derived)
    assert config == before
    assert not [item for item in derived.unresolved_references if item.field in {"destination_networks", "destination_ports"}]

    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    from openpyxl import load_workbook
    sheet = load_workbook(output, read_only=True)["Services"]
    headers = [cell.value for cell in sheet[1]]
    rows = [dict(zip(headers, row)) for row in sheet.iter_rows(min_row=2, values_only=True)]
    http = next(row for row in rows if row["Name"] == "HTTP")
    icmp = next(row for row in rows if row["Name"] == "ICMP Code")
    assert (http["Protocol"], http["Port"]) == ("6", "80")
    assert (icmp["Protocol"], icmp["Port"], icmp["ICMP Type"], icmp["ICMP Code"]) == ("1", None, "3", "1")
