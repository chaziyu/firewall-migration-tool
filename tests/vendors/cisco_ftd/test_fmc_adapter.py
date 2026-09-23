import json
from pathlib import Path

from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import CiscoFMCBundleParser


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"


def test_selected_fmc_domains_preserve_native_ownership_and_order():
    config = CiscoFMCBundleParser(FIXTURE.read_text(encoding="utf-8")).parse_source()
    assert [x.name for x in config.time_ranges] == ["business-hours"]
    assert config.managed_objects[0].raw["type"] == "FQDN"
    assert config.acp_rules[0].source_zones == ["inside"]
    assert config.acp_rules[0].destination_zones == ["outside"]
    assert config.intrusion_rule_overrides[0].source_attributes["parent_policy_id"] == "ips-1"
    assert config.s2s_vpn_endpoints[0].source_attributes["parent_topology_id"] == "vpn-1"
    assert config.ra_vpn_connection_profiles[0].source_attributes["parent_policy_id"] == "ra-1"
    assert config.routes[0].source_attributes["device_name"] == "FTD-A"
    assert config.dhcp_servers[0].source_attributes["device_id"] == "device-1"
    assert config.file_policies[0].raw["rules"][0]["order"] == 1


def test_canonical_networkaddresses_suppresses_historical_duplicates():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["objects"]["hosts"] = [{"id": "fqdn-1", "name": "updates"}]
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()
    assert [item.source_id for item in config.managed_objects].count("fqdn-1") == 1
