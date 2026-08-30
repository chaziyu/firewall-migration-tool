from fwmigrate.ir.enums import AddressType
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_ipv6_host_subnet_and_mixed_network_group_members_are_retained():
    parser = CiscoASAParser("""
object network V6_HOST
 host 2001:db8::1
object network V6_NET
 subnet 2001:db8:1::/64
object-group network MIXED
 network-object host 192.0.2.1
 network-object host 2001:db8::2
 network-object 2001:db8:2::/64
""")
    ir = parser.transform_to_ir()
    host = next(item for item in ir.addresses if item.name == "V6_HOST")
    subnet = next(item for item in ir.addresses if item.name == "V6_NET")
    group = next(item for item in ir.address_groups if item.name == "MIXED")
    assert host.type == AddressType.HOST and host.is_ipv6 and host.address_family == "ipv6"
    assert subnet.subnet == "2001:db8:1::/64" and subnet.is_ipv6
    assert group.address_family == "mixed"
    assert len(group.members) == 3
    assert sum(item.is_ipv6 for item in ir.addresses if item.name in group.members) == 2


def test_interface_ipv6_standby_dhcp_setroute_and_management_only_are_structured():
    parser = CiscoASAParser("""
interface Gi0/0
 nameif inside
 ip address 10.0.0.1 255.255.255.0 standby 10.0.0.2
 ipv6 address 2001:db8::1/64 standby 2001:db8::2
 ipv6 address 2001:db8:1::1/64 eui-64
 ipv6 address fe80::1/64 link-local
 management-only
interface Gi0/1
 ip address dhcp setroute
 ipv6 address autoconfig
 ipv6 address dhcp setroute
""")
    ir = parser.transform_to_ir()
    first = parser.config.interfaces[0]
    second = parser.config.interfaces[1]
    assert first.standby_ip == "10.0.0.2"
    assert first.management_only
    assert first.ipv6_addresses[0].standby == "2001:db8::2"
    assert first.ipv6_addresses[1].eui64
    assert first.ipv6_addresses[2].link_local
    assert second.dhcp_setroute and second.ipv6_autoconfig
    assert second.ipv6_dhcp and second.ipv6_dhcp_setroute
    assert ir.interfaces[0].source_attributes["standby_ip"] == "10.0.0.2"
    assert ir.interfaces[0].source_attributes["management_only"] is True
    assert ir.interfaces[1].source_attributes["dhcp_setroute"] is True
    assert len(ir.interfaces[0].ipv6_source_settings["addresses"]) == 3


def test_fqdn_v4_v6_family_is_preserved():
    ir = CiscoASAParser("""
object network DNS4
 fqdn v4 example.com
object network DNS6
 fqdn v6 ipv6.example.com
""").transform_to_ir()
    assert [(item.name, item.address_family) for item in ir.addresses] == [("DNS4", "ipv4"), ("DNS6", "ipv6")]
