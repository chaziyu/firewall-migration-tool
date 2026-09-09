from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import AddressType, PolicyAction
from tests.fixture_paths import JUNIPER_SRX_FIXTURE

def test_juniper_srx_parser_full_config():
    with open(JUNIPER_SRX_FIXTURE, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    ir = parser.parse(content)

    assert ir.metadata.hostname == "SRX-DC-Branch"
    assert ir.metadata.source_vendor == "juniper_srx"

    # Check Zones
    zone_names = [z.name for z in ir.zones]
    assert "trust" in zone_names
    assert "untrust" in zone_names
    assert "dmz" in zone_names

    # Check Addresses
    addr_names = [a.name for a in ir.addresses]
    assert "srv-web-01" in addr_names
    assert "net-branch-lan" in addr_names
    assert "fqdn-partner-api" in addr_names

    fqdn_addr = next(a for a in ir.addresses if a.name == "fqdn-partner-api")
    assert fqdn_addr.type == AddressType.FQDN
    assert fqdn_addr.value == "api.partner.io"

    # Check Address Groups (address-set)
    assert len(ir.address_groups) == 1
    assert ir.address_groups[0].name == "grp-branch-services"
    assert "srv-web-01" in ir.address_groups[0].members

    # Check Applications (Services)
    assert any(s.name == "app-custom-9000" for s in ir.services)
    assert any(sg.name == "app-web-stack" for sg in ir.service_groups)

    # Check Policies
    assert len(ir.policies) == 2
    pol1 = next(p for p in ir.policies if p.name == "Allow_Branch_To_Internet")
    assert pol1.action == PolicyAction.ALLOW
    assert "net-branch-lan" in pol1.source
    assert pol1.from_zone == ["trust"]
    assert pol1.to_zone == ["untrust"]

    # Check Routes
    assert len(ir.routes) == 1
    assert ir.routes[0].destination == "0.0.0.0/0"
    assert ir.routes[0].next_hop == "198.51.100.254"
