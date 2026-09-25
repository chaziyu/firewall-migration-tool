from pathlib import Path
from copy import deepcopy
from io import BytesIO
import json
from types import SimpleNamespace

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_ftd.source_report import extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views
from fwmigrate.vendors.cisco_ftd.export.excel import export_ftd_excel
from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import CiscoFMCBundleParser
from fwmigrate.vendors.cisco_ftd.model import CiscoFTDReference
from fwmigrate.vendors.cisco_ftd.validation import validate_ftd_config


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"


def test_identity_and_vpn_relationships_are_derived_without_source_mutation():
    result = extract_cisco_ftd_source(FIXTURE.read_text(encoding="utf-8"))
    before = deepcopy(result.config)
    derived = build_ftd_derived_views(result.config)
    assert any(item["relationship_type"] == "fmc-user-to-role" and item["owner_name"] == "operator"
               for item in derived.identity_relationships)
    assert derived.vpn_relationships[0]["endpoints"] == ["HQ"]
    assert result.config == before


def test_route_sla_monitor_is_a_typed_resolvable_source_reference():
    payload = {
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {"slamonitors": [{"id": "sla-1", "name": "WAN-Monitor"}]},
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {"static_routes": [
            {"id": "route-1", "name": "tracked-route", "slaMonitor": {
                "id": "sla-1", "name": "WAN-Monitor", "type": "SLAMonitor"}},
            {"id": "route-2", "name": "untracked-route"},
            {"id": "route-3", "name": "null-monitor-route", "slaMonitor": None},
            {"id": "route-4", "name": "missing-monitor-route", "slaMonitor": {
                "id": "sla-missing", "name": "missing"}},
        ]}}],
    }
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()
    tracked, untracked, null_monitor, missing = config.routes

    assert isinstance(tracked.sla_monitor, CiscoFTDReference)
    assert (tracked.sla_monitor.source_id, tracked.sla_monitor.name, tracked.sla_monitor.source_type) == (
        "sla-1", "WAN-Monitor", "SLAMonitor")
    assert config.sla_monitors[0].source_id == "sla-1"
    assert not any(item.source_attributes.get("resource_type") == "slamonitors" for item in config.native_resources)
    assert untracked.sla_monitor is None
    assert null_monitor.sla_monitor is None
    assert isinstance(missing.sla_monitor, CiscoFTDReference)

    before = deepcopy(config)
    derived = build_ftd_derived_views(config)
    assert any(item["owner"] == tracked.name and item["field"] == "sla_monitor"
               and item["kind"] == "SLA_MONITOR" for item in derived.resolved_references)
    issues = validate_ftd_config(config, derived).issues
    assert not any(item.source_object == tracked.name and "sla_monitor" in item.message for item in issues)
    assert not any(item.source_object == untracked.name and "sla_monitor" in item.message for item in issues)
    assert any(item.source_object == missing.name and "sla_monitor" in item.message
               and item.category == "unresolved-reference" for item in issues)
    assert config == before

    output = BytesIO()
    export_ftd_excel(SimpleNamespace(config=config, validation=SimpleNamespace(issues=issues)), output)
    sheet = load_workbook(output, read_only=True)["Routes"]
    assert [cell.value for cell in sheet[1]] == ["Name", "Device", "Virtual Router", "Interface", "Destination", "Gateway", "SLA Monitor",
        "Route Tracking", "Tunneled", "Source Plane", "Address Family", "Mask", "Normalized Destination(s)"]
    assert sheet[2][6].value == "WAN-Monitor"


def test_fmc_route_normalization_and_interface_topology_keep_device_scope():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d1"},
        "objects": {"networkaddresses": [
            {"id": "net4", "name": "IPv4 network", "type": "Network", "value": "10.0.0.0/24"},
            {"id": "net6", "name": "IPv6 network", "type": "Network", "value": "2001:db8::/64"}],
            "network_address_overrides": []},
        "devices": [
            {"id": "dev1", "name": "FTD-A", "resources": {"ftd_interfaces": [
                {"id": "if1", "name": "GigabitEthernet0/0", "interfaceType": "PhysicalInterface"},
                {"id": "if2", "name": "GigabitEthernet0/0.10", "interfaceType": "SubInterface"}],
                "static_routes": [
                    {"id": "r4", "name": "route4", "network": {"id": "net4", "name": "IPv4 network"}, "addressFamily": "iPv4"},
                    {"id": "r6", "name": "route6", "network": {"id": "net6", "name": "IPv6 network"}, "addressFamily": "IPv6"},
                    {"id": "null", "name": "null-route", "network": {"id": "net4", "name": "IPv4 network"}, "gateway": "Null0", "addressFamily": "IPv4"},
                    {"id": "missing", "name": "unresolved", "network": {"id": "missing", "name": "Missing"}, "addressFamily": "IPv4"},
                    {"id": "selected", "name": "selected-route", "selectedNetworks": [{"id": "net4", "name": "IPv4 network"}],
                     "gateway": {"literal": {"value": "10.0.0.1"}}, "routeTracking": {"slaMonitor": {"id": "sla1", "name": "SLA"}},
                     "isTunneled": True, "addressFamily": "IPv4"},
                    {"id": "mismatch", "name": "mismatch-route", "selectedNetworks": [{"id": "net6", "name": "IPv6 network"}],
                     "addressFamily": "IPv4"}]}},
            {"id": "dev2", "name": "FTD-B", "resources": {"ftd_interfaces": [
                {"id": "if3", "name": "GigabitEthernet0/0", "interfaceType": "PhysicalInterface"},
                {"id": "if4", "name": "GigabitEthernet0/0.10", "interfaceType": "SubInterface"}]}}]}
    result = extract_cisco_ftd_source(json.dumps(payload))
    before = result.config.model_dump()
    normalized = {item.source_name: item for item in result.derived.normalized_routes}
    assert normalized["route4"].normalized_destination == "10.0.0.0/24"
    assert normalized["route6"].normalized_destination == "2001:db8::/64"
    assert normalized["null-route"].gateway == "Null0"
    assert normalized["unresolved"].normalized_destination is None
    assert normalized["selected-route"].normalized_destination == "10.0.0.0/24"
    assert normalized["selected-route"].gateway == "10.0.0.1"
    assert normalized["selected-route"].issue is None
    assert normalized["mismatch-route"].issue
    assert any(item.source_object == "mismatch-route" and item.category == "invalid-route"
               for item in result.validation.issues)
    subinterfaces = [item for item in result.derived.interface_topology.interfaces
                     if item.name == "GigabitEthernet0/0.10"]
    assert {(item.device_id, item.parent, item.kind) for item in subinterfaces} == {
        ("dev1", "GigabitEthernet0/0", "subinterface"),
        ("dev2", "GigabitEthernet0/0", "subinterface")}
    assert result.config.model_dump() == before
