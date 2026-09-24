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
    assert [cell.value for cell in sheet[1]] == ["Name", "Interface", "Destination", "Gateway", "SLA Monitor",
        "Source Plane", "Address Family", "Mask", "Normalized Destination"]
    assert sheet[2][4].value == "WAN-Monitor"
