import fwmigrate.parsers
import pytest
import json
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration
from fwmigrate.extraction.models import ExtractionStatus


def test_parse_gaia_cli_text():
    gaia_cli = """
    # Gaia configuration script
    set hostname Branch-GW01
    set interface eth0 ipv4-address 192.168.1.1 mask-length 24
    set interface eth0 state on
    set interface eth0 comments "LAN Interface"
    set interface eth0 security-zone Internal
    set interface eth1 ipv4-address 203.0.113.2 mask-length 29
    set interface eth1 state on
    set interface eth1 security-zone External
    set static-route default nexthop gateway address 203.0.113.1 on
    set static-route 10.0.0.0/8 nexthop gateway address 192.168.1.254 on
    """

    meta, ifaces, zones, routes, inv, unsupp = parse_gaia_configuration(gaia_cli)

    assert meta.hostname == "Branch-GW01"
    assert len(ifaces) == 2
    eth0 = next(i for i in ifaces if i.name == "eth0")
    assert eth0.ip == "192.168.1.1/24"
    assert eth0.zone == "Internal"
    assert eth0.description == "LAN Interface"

    eth1 = next(i for i in ifaces if i.name == "eth1")
    assert eth1.ip == "203.0.113.2/29"
    assert eth1.zone == "External"

    assert len(zones) == 2
    zone_names = [z.name for z in zones]
    assert "Internal" in zone_names
    assert "External" in zone_names

    assert len(routes) == 2
    default_rt = next(r for r in routes if r.destination == "0.0.0.0/0")
    assert default_rt.next_hop == "203.0.113.1"


def test_checkpoint_parser_with_gaia_txt_input():
    gaia_cli = """
    set hostname Standalone-GW
    set interface eth0 ipv4-address 10.10.10.1 mask-length 24
    set static-route default nexthop gateway address 10.10.10.254 on
    """

    parser = PluginRegistry.get_parser("checkpoint")
    extraction = parser.extract(gaia_cli)
    ir = extraction.canonical_ir

    assert ir.metadata.hostname == "Standalone-GW"
    assert len(ir.interfaces) == 1
    assert ir.interfaces[0].name == "eth0"
    assert len(ir.routes) == 1


def test_gaia_ipv6_vlan_secondary_addresses_and_route_priority():
    text = """
    add interface eth0 vlan 10
    set interface eth0.10 ipv4-address 10.0.10.1 mask-length 24
    set interface eth0.10 ipv6-address 2001:db8:10::1 mask-length 64
    set static-route 10.20.0.0/16 nexthop gateway address 10.0.10.254 priority 20 on
    """
    _, interfaces, _, routes, _, _ = parse_gaia_configuration(text)
    interface = next(item for item in interfaces if item.name == "eth0.10")
    assert interface.vlanid == 10
    assert interface.parent == "eth0"
    assert interface.ip == "10.0.10.1/24"
    assert interface.secondary_ips[0].ip == "2001:db8:10::1/64"
    assert routes[0].priority == 20
    assert routes[0].administrative_distance is None


@pytest.mark.parametrize("line", [
    "set interface eth0 ipv4-address 999.1.1.1 mask-length 24",
    "set interface eth0 ipv4-address 10.0.0.1 mask-length 33",
    "set interface eth0 ipv6-address 2001:db8::1 mask-length 129",
])
def test_gaia_invalid_interface_addresses_are_parse_errors(line):
    _, interfaces, _, _, inventory, _ = parse_gaia_configuration(line)
    assert interfaces == []
    assert inventory[0].status == ExtractionStatus.PARSE_ERROR


def test_gaia_responses_bundle_field_is_consumed():
    parser = PluginRegistry.get_parser("checkpoint")
    extraction = parser.extract(json.dumps({
        "format": "checkpoint-export-v1",
        "gaia_responses": [{
            "command": "show configuration",
            "cli_text": "set hostname GaiaFieldGW\nset interface eth0 ipv4-address 10.1.1.1 mask-length 24",
        }],
    }))
    assert extraction.canonical_ir.metadata.hostname == "GaiaFieldGW"
    assert extraction.canonical_ir.interfaces[0].ip == "10.1.1.1/24"


def test_gaia_vlan_creates_child_and_preserves_parent():
    _, interfaces, _, _, inventory, _ = parse_gaia_configuration("""
    add interface eth0 vlan 10
    set interface eth0.10 ipv4-address 10.0.10.1 subnet-mask 255.255.255.0
    set interface eth0.10 state on
    """)
    parent = next(item for item in interfaces if item.name == "eth0")
    child = next(item for item in interfaces if item.name == "eth0.10")
    assert parent.interface_type == "physical"
    assert parent.vlanid is None
    assert child.interface_type == "vlan"
    assert child.parent == "eth0"
    assert child.vlanid == 10
    assert child.ip == "10.0.10.1/24"


def test_gaia_invalid_noncontiguous_subnet_mask_is_parse_error():
    _, interfaces, _, _, inventory, _ = parse_gaia_configuration(
        "set interface eth0 ipv4-address 10.0.0.1 subnet-mask 255.0.255.0"
    )
    assert interfaces == []
    assert inventory[0].status == ExtractionStatus.PARSE_ERROR


def test_gaia_r81_interface_tokens_and_loopback_creation():
    text = '''
    set interface eth0 link-speed 1000
    set interface eth0 mtu 1500
    set interface eth0 auto-negotiation on
    set interface eth0 mac-address 00:11:22:33:44:55
    set interface eth0 ipv6-autoconfig off
    set interface eth0 monitor-mode off
    set interface eth0 speed 1000
    add interface lo loopback 192.0.2.10/32
    set interface lo state on
    set interface lo comments "Management loopback"
    add bridging group 1
    set bridging group 1 interface eth0
    '''

    _, interfaces, _, _, inventory, _ = parse_gaia_configuration(text)

    eth0 = next(item for item in interfaces if item.name == "eth0")
    assert eth0.source_attributes["link-speed"] == "1000"
    assert eth0.source_attributes["mtu"] == "1500"
    assert eth0.source_attributes["auto-negotiation"] == "on"
    assert eth0.source_attributes["mac-address"] == "00:11:22:33:44:55"
    assert eth0.source_attributes["ipv6-autoconfig"] == "off"
    assert eth0.source_attributes["monitor-mode"] == "off"

    loopback = next(item for item in interfaces if item.name == "lo")
    assert loopback.interface_type == "loopback"
    assert loopback.ip == "192.0.2.10/32"
    assert loopback.description == "Management loopback"

    legacy_speed = next(item for item in inventory if item.name == "eth0_speed")
    assert legacy_speed.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert legacy_speed.requires_manual_review is True

    bridge_items = [item for item in inventory if item.source_type == "gaia-bridging-group"]
    assert len(bridge_items) == 2
    assert bridge_items[0].source_attributes["raw_command"] == "add bridging group 1"
    assert bridge_items[1].source_attributes["raw_command"] == "set bridging group 1 interface eth0"


def test_gaia_r81_static_route_tokens_are_quote_aware():
    line = (
        'set static-route 10.0.0.0/8 nexthop gateway logical eth1 '
        'priority 10 scopelocal comment "route through primary WAN" on'
    )

    _, _, _, routes, inventory, _ = parse_gaia_configuration(line)

    assert routes == []
    route = inventory[0]
    assert route.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert route.requires_manual_review is True
    assert route.source_attributes["interface"] == "eth1"
    assert route.source_attributes["priority"] == 10
    assert route.source_attributes["unmodeled"]["scopelocal"] is True
    assert route.source_attributes["unmodeled"]["comment"] == "route through primary WAN"
    assert route.source_attributes["raw_command"] == line
