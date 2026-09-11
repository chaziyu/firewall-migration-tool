from fwmigrate.parsers.cisco_ftd.parser import CiscoFTDParser


def test_ftd_management_interface_block_is_structured_without_zone_inference():
    parser = CiscoFTDParser(
        """
configure network ipv4 manual 192.0.2.10 255.255.255.0 192.0.2.1
configure ssh-access-list 192.0.2.0/24
interface Management1/1
 management-only
 nameif diagnostic
 security-level 0
 ip address 192.0.2.10 255.255.255.0
 mtu 1500
 no shutdown
"""
    )
    cfg = parser.parse_raw()

    assert cfg.management_ipv4 == "192.0.2.10"
    assert cfg.management_gateway == "192.0.2.1"
    assert cfg.diagnostic_interface == "Management1/1"
    assert len(cfg.interfaces) == 1
    interface = cfg.interfaces[0]
    assert interface.name == "Management1/1"
    assert interface.nameif == "diagnostic"
    assert interface.management_only is True
    assert interface.security_level == 0
    assert interface.ip == "192.0.2.10"
    assert interface.mask == "255.255.255.0"
    assert interface.mtu == 1500

    ir = parser.parse()
    assert len(ir.interfaces) == 1
    ir_interface = ir.interfaces[0]
    assert ir_interface.name == "Management1/1"
    assert ir_interface.zone is None
    assert ir_interface.ip == "192.0.2.10/24"
    assert ir_interface.interface_type == "management"
    assert ir_interface.source_attributes["nameif"] == "diagnostic"
    assert ir_interface.source_attributes["ftd_policy_zone_not_inferred"] is True


def test_ftd_cmi_and_negated_management_state_are_retained():
    parser = CiscoFTDParser(
        """
show management-interface convergence
no management-interface convergence
management dns-server 8.8.8.8 1.1.1.1
"""
    )
    cfg = parser.parse_raw()

    assert cfg.cmi_enabled is False
    assert cfg.management_dns_servers == ["8.8.8.8", "1.1.1.1"]
    assert any(item.source_attributes.get("negated") for item in cfg.management_settings)


def test_ftd_subinterface_ipv6_and_static_routes_are_structured():
    parser = CiscoFTDParser("""
interface GigabitEthernet0/1
 no shutdown
interface GigabitEthernet0/1.100
 vlan 100
 ipv6 address 2001:db8::1/64
 no shutdown
route GigabitEthernet0/1 0.0.0.0 0.0.0.0 192.0.2.1
ipv6 route GigabitEthernet0/1 2001:db8:1::/64 2001:db8::2
""")
    config = parser.parse_raw()
    child = config.interfaces[1]
    assert (child.interface_type, child.parent_interface, child.vlan_id) == (
        "subinterface", "GigabitEthernet0/1", 100
    )
    assert config.interfaces[1].ipv6_addresses[0].prefix_length == 64
    ir = parser.parse()
    assert [route.address_family for route in ir.routes] == ["ipv4", "ipv6"]
    assert ir.routes[0].destination == "0.0.0.0/0"
