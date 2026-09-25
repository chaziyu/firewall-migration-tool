import json
from io import BytesIO
from pathlib import Path
from openpyxl import load_workbook

from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import CiscoFMCBundleParser
from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter, extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views
from fwmigrate.vendors.cisco_ftd.validation import validate_ftd_config
from fwmigrate.vendors.cisco_ftd.export.excel import export_ftd_excel
from fwmigrate.vendors.cisco_ftd.web_report import build_ftd_preview


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"

def test_selected_fmc_domains_preserve_native_ownership_and_order():
    config = CiscoFMCBundleParser(FIXTURE.read_text(encoding="utf-8")).parse_source()
    assert [x.name for x in config.time_ranges] == ["business-hours"]
    assert config.network_addresses[0].raw_extra["type"] == "FQDN"
    assert config.access_control_policies[0].rules[0].source_zones[0].name == "inside"
    assert config.access_control_policies[0].rules[0].destination_zones[0].name == "outside"
    assert len(config.intrusion_rule_groups) == 1
    assert not config.intrusion_rule_behaviors
    assert not config.intrusion_rule_overrides
    assert not [item for item in config.native_resources
                if item.source_attributes.get("parent_policy_type") == "intrusionpolicies"]
    assert config.s2s_vpn_endpoints[0].source_attributes["parent_topology_id"] == "vpn-1"
    assert config.ra_vpn_connection_profiles[0].source_attributes["parent_policy_id"] == "ra-1"
    assert config.routes[0].source_attributes["device_name"] == "FTD-A"
    assert config.dhcp_servers[0].source_attributes["device_id"] == "device-1"
    assert config.file_policies[0].rules[0].position == 1
    assert config.file_policies[0].rules[0].collection_order == 1
    assert "rules" not in config.file_policies[0].raw_extra
