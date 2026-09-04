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


def test_gaia_static_routes_are_family_aware_and_preserve_route_fields():
    _, _, _, routes, _, _ = parse_gaia_configuration("""
    set static-route default nexthop gateway address 192.0.2.1 priority 7 on
    set ipv6 static-route default nexthop gateway 2001:db8::1 priority 2 on
    set ipv6 static-route 2001:db8:1::/64 nexthop interface eth2 priority 3 on
    set static-route 198.51.100.0/24 nexthop gateway logical eth1 comment "WAN path" priority 1 on
    """)

    assert [(route.address_family, route.destination) for route in routes] == [
        ("ipv4", "0.0.0.0/0"),
        ("ipv6", "::/0"),
        ("ipv6", "2001:db8:1::/64"),
        ("ipv4", "198.51.100.0/24"),
    ]
    assert routes[0].next_hop == "192.0.2.1"
    assert routes[1].next_hop == "2001:db8::1"
    assert routes[2].interface == "eth2"
    assert routes[3].interface == "eth1"
    assert routes[3].priority == 1
    assert routes[3].description == "WAN path"


def test_gaia_static_route_unsupported_actions_and_monitoring_stay_source_only():
    _, _, _, routes, inventory, _ = parse_gaia_configuration("""
    set static-route 192.0.2.0/24 nexthop blackhole
    set ipv6 static-route 2001:db8::/64 nexthop reject
    set static-route 198.51.100.0/24 rank 100
    set static-route 203.0.113.0/24 nexthop gateway address 192.0.2.1 monitored-ip 198.51.100.1 on
    """)

    assert routes == []
    assert [item.source_attributes.get("nexthop_type") for item in inventory] == [
        "blackhole", "reject", "rank", "gateway",
    ]
    assert inventory[2].source_attributes["unmodeled"]["rank"] == "100"
    assert inventory[3].source_attributes["unmodeled"]["monitored-ip"] == [
        {"address": "198.51.100.1", "state": "on"},
    ]
    assert all(item.status == ExtractionStatus.PARTIALLY_NORMALIZED for item in inventory)


def test_gaia_static_route_multiple_next_hops_keep_order_and_duplicates():
    _, _, _, routes, _, _ = parse_gaia_configuration("""
    set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.1 on
    set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.2 on
    set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.1 on
    """)

    assert [route.next_hop for route in routes] == ["192.0.2.1", "192.0.2.2", "192.0.2.1"]
    assert [route.name for route in routes] == [
        "static_10.0.0.0/8_192.0.2.1",
        "static_10.0.0.0/8_192.0.2.2",
        "static_10.0.0.0/8_192.0.2.1_2",
    ]


def test_gaia_invalid_ipv6_route_does_not_become_default():
    _, _, _, routes, inventory, _ = parse_gaia_configuration(
        "set ipv6 static-route not-an-ipv6-prefix nexthop gateway 2001:db8::1 on"
    )

    assert routes == []
    assert inventory[0].status == ExtractionStatus.PARSE_ERROR
    assert inventory[0].source_attributes["destination"] == "not-an-ipv6-prefix"


def test_gaia_bonding_group_merges_commands_in_arbitrary_order():
    _, interfaces, _, _, inventory, _ = parse_gaia_configuration("""
    set interface bond7 comments "WAN bond"
    set interface bond7 ipv4-address 192.0.2.7 mask-length 24
    set interface eth2 state on
    set bonding group 7 mode active-backup primary eth2
    add bonding group 7 interface eth3
    add bonding group 7
    set bonding group 7 down-delay 250
    add bonding group 7 interface eth2
    set bonding group 7 mii-interval 100
    """)

    bond = next(item for item in interfaces if item.name == "bond7")
    assert bond.interface_type == "aggregate"
    assert bond.members == ["eth3", "eth2"]
    assert bond.ip == "192.0.2.7/24"
    assert bond.description == "WAN bond"
    assert bond.source_attributes["bond_mode"] == "active-backup"
    assert bond.source_attributes["bond_primary"] == "eth2"
    assert bond.source_attributes["bond_down_delay"] == "250"
    assert bond.source_attributes["bond_member_states"] == {"eth2": "on"}
    assert bond.requires_manual_review is True
    assert len([item for item in inventory if item.source_type == "gaia-bonding-group"]) == 6


def test_gaia_bridge_preserves_members_and_interface_settings():
    _, interfaces, _, _, inventory, _ = parse_gaia_configuration("""
    set interface br5 state on
    set interface br5 ipv6-address 2001:db8:5::1 mask-length 64
    add bridging group 5 interface eth5
    add bridging group 5
    set interface br5 comments "Transit bridge"
    add bridging group 5 interface eth6
    """)

    bridge = next(item for item in interfaces if item.name == "br5")
    assert bridge.interface_type == "bridge"
    assert bridge.status is True
    assert bridge.ip == "2001:db8:5::1/64"
    assert bridge.description == "Transit bridge"
    assert bridge.source_attributes["bridge_members"] == ["eth5", "eth6"]
    assert bridge.source_attributes["bridging_group_id"] == 5
    assert bridge.requires_manual_review is True
    assert len([item for item in inventory if item.source_type == "gaia-bridging-group"]) == 3


def test_gaia_loopback_generated_name_merges_with_explicit_settings():
    _, interfaces, _, _, _, _ = parse_gaia_configuration("""
    set interface loop00 comments "Router ID"
    set interface loop00 state on
    set interface loop00 ipv6-address 2001:db8::1 mask-length 128
    add interface lo loopback 198.51.100.1/32
    """)

    assert [item.name for item in interfaces].count("loop00") == 1
    assert not any(item.name == "lo" for item in interfaces)
    loopback = next(item for item in interfaces if item.name == "loop00")
    assert loopback.interface_type == "loopback"
    assert loopback.ip == "198.51.100.1/32"
    assert loopback.secondary_ips[0].ip == "2001:db8::1/128"
    assert loopback.description == "Router ID"


def test_gaia_system_settings_are_structured_and_snmp_is_redacted_inventory():
    _, _, _, _, inventory, _ = parse_gaia_configuration("""
    set dns primary 192.0.2.53
    set dns secondary 198.51.100.53
    set dns tertiary 203.0.113.53
    set domain-name corp.example
    set ntp active on
    set ntp server primary ntp.corp.example version 4
    set snmp agent on
    set snmp version v2
    set snmp community SuperSecret read-only
    set snmp contact admin@corp.example
    set snmp location DC1
    """)

    dns = {item.source_attributes["setting"]: item.source_attributes["value"]
           for item in inventory if item.source_type == "gaia-dns"}
    assert dns == {"primary": "192.0.2.53", "secondary": "198.51.100.53", "tertiary": "203.0.113.53"}
    assert any(item.source_type == "gaia-domain-name" for item in inventory)
    ntp = next(item for item in inventory if item.source_type == "gaia-ntp" and item.source_attributes["setting"] == "server")
    assert ntp.source_attributes["role"] == "primary"
    assert ntp.source_attributes["address"] == "ntp.corp.example"
    community = next(item for item in inventory if item.source_type == "gaia-snmp" and item.source_attributes["setting"] == "community")
    assert community.source_attributes["community"] == "[REDACTED]"
