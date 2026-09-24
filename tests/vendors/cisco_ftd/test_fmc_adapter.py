import json
from pathlib import Path

from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import CiscoFMCBundleParser


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"


def test_selected_fmc_domains_preserve_native_ownership_and_order():
    config = CiscoFMCBundleParser(FIXTURE.read_text(encoding="utf-8")).parse_source()
    assert [x.name for x in config.time_ranges] == ["business-hours"]
    assert config.network_addresses[0].raw_extra["type"] == "FQDN"
    assert config.access_control_policies[0].rules[0].source_zones[0].name == "inside"
    assert config.access_control_policies[0].rules[0].destination_zones[0].name == "outside"
    assert config.intrusion_rule_overrides[0].source_attributes["parent_policy_id"] == "ips-1"
    assert config.s2s_vpn_endpoints[0].source_attributes["parent_topology_id"] == "vpn-1"
    assert config.ra_vpn_connection_profiles[0].source_attributes["parent_policy_id"] == "ra-1"
    assert config.routes[0].source_attributes["device_name"] == "FTD-A"
    assert config.dhcp_servers[0].source_attributes["device_id"] == "device-1"
    assert config.file_policies[0].raw_extra["rules"][0]["order"] == 1


def test_canonical_networkaddresses_suppresses_historical_duplicates():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["objects"]["hosts"] = [{"id": "fqdn-1", "name": "updates"}]
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()
    assert [item.source_id for item in config.network_addresses].count("fqdn-1") == 1


def test_typed_source_fields_keep_reference_identity_and_missing_state():
    payload = {
        "source": "fmc-rest-api",
        "objects": {"networkgroups": [
            {"id": "missing-members", "name": "Missing"},
            {"id": "empty-members", "name": "Empty", "objects": []},
            {"id": "members", "name": "Members", "objects": [
                {"id": "host-1", "name": "server", "type": "Host"}
            ]},
        ]},
    }
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()

    assert not hasattr(config, "managed_objects")
    assert [group.members for group in config.network_groups[:2]] == [None, []]
    reference = config.network_groups[2].members[0]
    assert (reference.source_id, reference.name, reference.source_type) == ("host-1", "server", "Host")
