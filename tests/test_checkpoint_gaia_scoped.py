from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.checkpoint.gaia_scoped import (
    parse_gaia_configuration,
    split_virtual_system_contexts,
)


def test_virtual_system_context_switches_are_explicit_and_sticky():
    contexts, switches = split_virtual_system_contexts("""
set hostname vsx-gw
set virtual-system 2
set interface eth0 ipv4-address 10.2.0.1 mask-length 24
set virtual-system 5
set interface eth0 ipv4-address 10.5.0.1 mask-length 24
set virtual-system 2
set static-route default nexthop gateway address 10.2.0.254 on
""")
    assert list(contexts) == [None, 2, 5]
    assert len(switches) == 3
    assert any("10.2.0.1" in line for line in contexts[2])
    assert any("10.2.0.254" in line for line in contexts[2])
    assert any("10.5.0.1" in line for line in contexts[5])


def test_same_interface_and_route_identity_remain_separate_across_vsids():
    _, interfaces, _, routes, inventory, _ = parse_gaia_configuration("""
set virtual-system 2
set interface eth0 ipv4-address 10.2.0.1 mask-length 24
set interface eth0 state on
set static-route default nexthop gateway address 10.2.0.254 on
set virtual-system 5
set interface eth0 ipv4-address 10.5.0.1 mask-length 24
set interface eth0 state on
set static-route default nexthop gateway address 10.5.0.254 on
""", domain="D1", gateway="VSX-GW")

    eth0 = [item for item in interfaces if item.name == "eth0"]
    assert len(eth0) == 2
    assert {item.ip for item in eth0} == {"10.2.0.1/24", "10.5.0.1/24"}
    assert {item.source_attributes["virtual_system_id"] for item in eth0} == {2, 5}
    assert {item.source_context for item in eth0} == {"VSX-GW:vsid=2", "VSX-GW:vsid=5"}

    assert len(routes) == 2
    assert {route.source_attributes["virtual_system_id"] for route in routes} == {2, 5}
    assert {route.source_context for route in routes} == {"VSX-GW:vsid=2", "VSX-GW:vsid=5"}

    switches = [item for item in inventory if item.source_type == "gaia-virtual-system-context"]
    assert len(switches) == 2
    assert all(item.status == ExtractionStatus.NORMALIZED for item in switches)


def test_bond_member_delete_updates_effective_ordered_state():
    _, interfaces, _, _, _, _ = parse_gaia_configuration("""
add bonding group 1
add bonding group 1 interface eth1
add bonding group 1 interface eth2
set bonding group 1 mode 8023AD lacp-rate fast xmit-hash-policy layer3+4
set bonding group 1 interface eth2 state off
delete bonding group 1 interface eth1
""")
    bond = next(item for item in interfaces if item.name == "bond1")
    assert bond.members == ["eth2"]
    assert bond.source_attributes["bond_member_states"] == {"eth2": "off"}
    assert bond.source_attributes["bond_deleted_members"] == ["eth1"]
    settings = bond.source_attributes["bond_settings"]
    assert settings["mode"] == "8023AD"
    assert settings["lacp-rate"] == "fast"
    assert settings["xmit-hash-policy"] == "layer3+4"


def test_bridge_member_delete_does_not_leave_stale_membership():
    _, interfaces, _, _, _, _ = parse_gaia_configuration("""
add bridging group 10
add bridging group 10 interface eth1
add bridging group 10 interface eth2
add bridging group 10 interface eth3
set interface br10 state on
delete bridging group 10 interface eth2
""")
    bridge = next(item for item in interfaces if item.name == "br10")
    assert bridge.members == ["eth1", "eth3"]
    assert bridge.source_attributes["bridge_deleted_members"] == ["eth2"]


def test_interface_properties_use_shlex_and_project_safe_fields():
    _, interfaces, _, _, _, _ = parse_gaia_configuration("""
set interface eth0 comments "WAN uplink with spaces"
set interface eth0 mtu 9000
set interface eth0 link-speed 1000M/full
set interface eth0 auto-negotiation on
set interface eth0 monitor-mode on
set interface eth0 ipv6-autoconfig on
""")
    interface = next(item for item in interfaces if item.name == "eth0")
    assert interface.description == "WAN uplink with spaces"
    assert interface.mtu == 9000
    assert interface.source_speed == "1000M/full"
    assert interface.source_ipv6_autoconf == "on"
    assert interface.source_attributes["auto_negotiation"] == "on"
    assert interface.source_attributes["monitor_mode"] == "on"
    assert interface.migration_status == "PARTIALLY_NORMALIZED"


def test_dns_keeps_domain_and_repeated_search_suffixes_separate_per_vsid():
    _, _, _, _, inventory, _ = parse_gaia_configuration("""
set virtual-system 3
set dns primary 2001:db8::53
set dns secondary 192.0.2.53
set dns search corp.example
set dns search lab.example
set domainname system.example
set virtual-system 4
set dns primary 203.0.113.53
set dns search branch.example
set domainname branch-system.example
""")
    records = [item for item in inventory if item.source_type == "gaia-dns-effective"]
    assert len(records) == 2
    by_vsid = {item.source_attributes["virtual_system_id"]: item for item in records}
    assert by_vsid[3].source_attributes["search_suffixes"] == ["corp.example", "lab.example"]
    assert by_vsid[3].source_attributes["system_domain_name"] == "system.example"
    assert by_vsid[3].source_attributes["servers"] == {
        "primary": "2001:db8::53", "secondary": "192.0.2.53",
    }
    assert by_vsid[4].source_attributes["search_suffixes"] == ["branch.example"]


def test_invalid_dns_server_is_parse_error_without_affecting_other_context():
    _, _, _, _, inventory, _ = parse_gaia_configuration("""
set virtual-system 1
set dns primary not-an-ip
set virtual-system 2
set dns primary 192.0.2.53
""")
    records = [item for item in inventory if item.source_type == "gaia-dns-effective"]
    by_vsid = {item.source_attributes["virtual_system_id"]: item for item in records}
    assert by_vsid[1].status == ExtractionStatus.PARSE_ERROR
    assert by_vsid[2].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_dhcp_effective_state_accumulates_and_applies_delete_semantics():
    _, _, _, _, inventory, _ = parse_gaia_configuration("""
set dhcp server enable
add dhcp server subnet 10.0.0.0 netmask 255.255.255.0
set dhcp server subnet 10.0.0.0 dns 192.0.2.53,192.0.2.54
add dhcp server subnet 10.0.0.0 include-ip-pool 10.0.0.10-10.0.0.20
add dhcp server subnet 10.0.0.0 include-ip-pool 10.0.0.30-10.0.0.40
delete dhcp server subnet 10.0.0.0 include-ip-pool 10.0.0.10-10.0.0.20
""")
    effective = next(item for item in inventory if item.source_type == "gaia-dhcp-effective")
    assert effective.source_attributes["dns_servers"] == ["192.0.2.53", "192.0.2.54"]
    assert effective.source_attributes["pools"] == [
        {"type": "include", "value": "10.0.0.30-10.0.0.40"},
    ]
    assert effective.source_attributes["enabled"] is True


def test_timezone_and_ntp_servers_are_accumulated_in_context():
    _, _, _, _, inventory, _ = parse_gaia_configuration("""
set timezone Asia/Kuala_Lumpur
set ntp active on
set ntp server primary 192.0.2.10 version 4
set ntp server secondary 2001:db8::10 version 4
""")
    effective = next(item for item in inventory if item.source_type == "gaia-system-effective")
    assert effective.source_attributes["timezone"] == "Asia/Kuala_Lumpur"
    assert effective.source_attributes["ntp_enabled"] is True
    assert len(effective.source_attributes["ntp_servers"]) == 2