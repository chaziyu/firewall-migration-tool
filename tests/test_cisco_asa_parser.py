from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import AddressType, PolicyAction, NATType
from tests.fixture_paths import CISCO_ASA_FIXTURE

def test_cisco_asa_parser_full_config():
    with open(CISCO_ASA_FIXTURE, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("cisco_asa")
    ir = parser.parse(content)

    assert ir.metadata.hostname == "ASA-Core-DC"
    assert ir.metadata.source_vendor == "cisco_asa"

    # Check Zones
    zone_names = [z.name for z in ir.zones]
    assert "inside" in zone_names
    assert "outside" in zone_names
    assert "dmz" in zone_names

    # Check Addresses
    addr_names = [a.name for a in ir.addresses]
    assert "Web_Server_01" in addr_names
    assert "App_Server_Subnet" in addr_names
    assert "DB_Range" in addr_names
    assert "API_External_FQDN" in addr_names

    web_server = next(a for a in ir.addresses if a.name == "Web_Server_01")
    assert web_server.value == "172.16.10.80"
    assert web_server.type == AddressType.HOST

    app_subnet = next(a for a in ir.addresses if a.name == "App_Server_Subnet")
    assert app_subnet.value == "10.0.1.0/24"
    assert app_subnet.type == AddressType.NETWORK

    # Check Address Groups
    assert len(ir.address_groups) >= 1
    grp = next(g for g in ir.address_groups if g.name == "Grp_DC_Servers")
    assert len(grp.members) == 3

    # Check Services & Groups
    assert len(ir.service_groups) >= 1
    sgrp = next(sg for sg in ir.service_groups if sg.name == "Grp_Web_Services")
    assert len(sgrp.members) >= 1

    # Check Policies
    assert len(ir.policies) >= 3
    permit_rules = [p for p in ir.policies if p.action == PolicyAction.ALLOW]
    assert len(permit_rules) >= 2

    # Check NAT
    assert len(ir.nat_rules) >= 2
    static_nat = next((n for n in ir.nat_rules if n.translated_source == "198.51.100.5"), None)
    assert static_nat is not None

    # Check Routes
    assert len(ir.routes) >= 2
