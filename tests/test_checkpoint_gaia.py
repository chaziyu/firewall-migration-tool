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


def test_gaia_ipv6_vlan_secondary_addresses_and_route_distance():
    text = """
    set interface eth0.10 vlan-id 10
    set interface eth0.10 ipv4-address 10.0.10.1 mask-length 24
    set interface eth0.10 ipv6-address 2001:db8:10::1 mask-length 64
    set static-route 10.20.0.0/16 nexthop gateway address 10.0.10.254 on priority 20 distance 5
    """
    _, interfaces, _, routes, _, _ = parse_gaia_configuration(text)
    interface = interfaces[0]
    assert interface.vlanid == 10
    assert interface.parent == "eth0"
    assert interface.ip == "10.0.10.1/24"
    assert interface.secondary_ips[0].ip == "2001:db8:10::1/64"
    assert routes[0].priority == 20
    assert routes[0].administrative_distance == 5


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
