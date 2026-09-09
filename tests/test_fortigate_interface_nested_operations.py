"""Tests for FortiGate nested interface configuration and command operations.

Verifies:
- Evaluation of set, unset, append commands in nested interface blocks.
- List-valued fields such as ip6-allowaccess.
- Child collections (ip6-extra-addr, ip6-prefix-list, vrrp, vrrp6).
- Lossless preservation of raw FGSourceNode operations alongside typed effective state.
"""

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_interface_nested_ipv6_set_unset_append_operations() -> None:
    config = """
config system interface
    edit "port1"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping https
        append allowaccess ssh
        config ipv6
            set ip6-address 2001:db8:1::1/64
            set ip6-allowaccess ping https
            append ip6-allowaccess ssh snmp
            set autoconf enable
            unset autoconf
            set ip6-manage-flag enable
            set ip6-other-flag enable
            unset ip6-other-flag
            config ip6-extra-addr
                edit "2001:db8:1::2/64"
                next
                edit "2001:db8:1::3/64"
                next
            end
            config ip6-prefix-list
                edit "2001:db8:1::/64"
                    set autonomous-flag enable
                    set onlink-flag enable
                    set preferred-life-time 3600
                    set valid-life-time 7200
                    set rdnss "2001:db8:1::53"
                    append rdnss "2001:db8:1::54"
                    set dnssl "example.com"
                    unset dnssl
                next
            end
            config vrrp6
                edit 1
                    set vrip6 2001:db8:1::254
                    set priority 100
                    set adv-interval 1
                    set preempt enable
                next
            end
        end
    next
end
"""
    cfg = parse_fortigate_config(config)
    assert len(cfg.interfaces) == 1
    intf = cfg.interfaces[0]

    # Effective IPv4 state
    assert intf.name == "port1"
    assert intf.ip == "192.0.2.1 255.255.255.0"
    assert intf.allowaccess == ["ping", "https", "ssh"]

    # Effective IPv6 state
    assert intf.ip6_address == "2001:db8:1::1/64"
    assert intf.ip6_allowaccess == ["ping", "https", "ssh", "snmp"]
    assert intf.ipv6_autoconf is None
    assert intf.ip6_manage_flag == "enable"
    assert intf.ip6_other_flag is None
    assert "ipv6_autoconf" not in intf.source_explicit_fields

    # Nested extra addresses
    assert len(intf.ipv6_extra_addresses) == 2
    assert intf.ipv6_extra_addresses[0].source_address == "2001:db8:1::2/64"
    assert intf.ipv6_extra_addresses[1].source_address == "2001:db8:1::3/64"

    # Nested prefix advertisements
    assert len(intf.ipv6_prefix_advertisements) == 1
    prefix = intf.ipv6_prefix_advertisements[0]
    assert prefix.prefix == "2001:db8:1::/64"
    assert prefix.preferred_life_time == 3600
    assert prefix.valid_life_time == 7200
    assert prefix.rdnss == ["2001:db8:1::53", "2001:db8:1::54"]
    assert prefix.dnssl == []

    # Nested VRRP6
    assert len(intf.vrrp6) == 1
    vrrp6 = intf.vrrp6[0]
    assert vrrp6.vrid == 1
    assert vrrp6.vrip6 == "2001:db8:1::254"
    assert vrrp6.priority == 100
    assert vrrp6.preempt == "enable"

    # Raw lossless source representation
    assert len(intf.nested_configs) >= 1
    ipv6_node = next(n for n in intf.nested_configs if n.name == "ipv6")
    ops = [(c.operation, c.key) for c in ipv6_node.commands]
    assert ("set", "ip6-address") in ops
    assert ("set", "ip6-allowaccess") in ops
    assert ("append", "ip6-allowaccess") in ops
    assert ("set", "autoconf") in ops
    assert ("unset", "autoconf") in ops
    assert ("set", "ip6-other-flag") in ops
    assert ("unset", "ip6-other-flag") in ops


def test_interface_nested_vrrp_and_proxy_arp_operations() -> None:
    config = """
config system interface
    edit "port2"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        config vrrp
            edit 10
                set vrip 10.0.0.254
                set priority 200
                set version 3
                set status enable
                set adv-interval 2
                unset adv-interval
                config proxy-arp
                    edit 1
                        set ip 10.0.0.100
                    next
                    edit 2
                        set ip 10.0.0.101
                    next
                end
            next
        end
    next
end
"""
    cfg = parse_fortigate_config(config)
    assert len(cfg.interfaces) == 1
    intf = cfg.interfaces[0]

    assert len(intf.vrrp) == 1
    v = intf.vrrp[0]
    assert v.vrid == 10
    assert v.vrip == "10.0.0.254"
    assert v.priority == 200
    assert v.version == 3
    assert v.status == "enable"
    assert v.adv_interval is None

    assert len(v.proxy_arp) == 2
    assert v.proxy_arp[0].ip == "10.0.0.100"
    assert v.proxy_arp[1].ip == "10.0.0.101"


def test_interface_multiple_edit_blocks_and_quoted_values() -> None:
    config = """
config system interface
    edit "port3"
        set vdom "root"
        set mode dhcp
        set defaultgw enable
        set description "Uplink to ISP A"
        config egress-queues
            set cos0 "queue-0"
            set cos1 "queue-1"
            unset cos1
        end
    next
    edit "port4"
        set vdom "root"
        set type vlan
        set vlanid 100
        set interface "port3"
        set description "VLAN 100 DMZ"
        set ip 172.16.100.1 255.255.255.0
        config client-options
            edit 1
                set code 60
                set type hex
                set value "466f72746947617465"
            next
        end
    next
end
"""
    cfg = parse_fortigate_config(config)
    assert len(cfg.interfaces) == 2

    p3 = cfg.interfaces[0]
    assert p3.name == "port3"
    assert p3.mode == "dhcp"
    assert p3.defaultgw == "enable"
    assert p3.description == "Uplink to ISP A"
    assert p3.egress_queues is not None
    assert p3.egress_queues.cos0 == "queue-0"
    assert p3.egress_queues.cos1 is None

    p4 = cfg.interfaces[1]
    assert p4.name == "port4"
    assert p4.type == "vlan"
    assert p4.vlanid == 100
    assert p4.interface == "port3"
    assert p4.description == "VLAN 100 DMZ"
    assert p4.ip == "172.16.100.1 255.255.255.0"
    assert len(p4.client_options) == 1
    assert p4.client_options[0].code == 60
    assert p4.client_options[0].type == "hex"
    assert p4.client_options[0].value == "466f72746947617465"


def test_vlan_interfaces_with_identical_vlanid_across_parents_and_vdoms() -> None:
    config = """
config vdom
    edit "root"
        config system interface
            edit "port1"
                set type physical
            next
            edit "port2"
                set type physical
            next
            edit "vlan100_p1"
                set type vlan
                set vlanid 100
                set interface "port1"
                set vrf 1
                set ip 10.1.1.1 255.255.255.0
                set role lan
                set status up
                set allowaccess ping https
            next
            edit "vlan100_p2"
                set type vlan
                set vlanid 100
                set interface "port2"
                set vrf 2
                set ip 10.2.2.1 255.255.255.0
                set role dmz
                set status up
                set allowaccess ping ssh
            next
        end
    next
    edit "tenant-b"
        config system interface
            edit "port1"
                set type physical
            next
            edit "vlan100_tenant"
                set type vlan
                set vlanid 100
                set interface "port1"
                set ip 10.3.3.1 255.255.255.0
                config ipv6
                    set ip6-address 2001:db8:100::1/64
                    set ip6-allowaccess ping https
                end
            next
        end
    next
end
"""
    cfg = parse_fortigate_config(config)
    vlans = [intf for intf in cfg.interfaces if intf.type == "vlan"]
    assert len(vlans) == 3

    # Identical VLAN ID 100 on parent port1 in root
    v1 = next(intf for intf in vlans if intf.name == "vlan100_p1")
    assert v1.vdom == "root"
    assert v1.vlanid == 100
    assert v1.interface == "port1"
    assert v1.vrf == 1
    assert v1.ip == "10.1.1.1 255.255.255.0"
    assert v1.role == "lan"
    assert v1.status == "up"
    assert v1.allowaccess == ["ping", "https"]

    # Identical VLAN ID 100 on parent port2 in root
    v2 = next(intf for intf in vlans if intf.name == "vlan100_p2")
    assert v2.vdom == "root"
    assert v2.vlanid == 100
    assert v2.interface == "port2"
    assert v2.vrf == 2
    assert v2.ip == "10.2.2.1 255.255.255.0"
    assert v2.role == "dmz"
    assert v2.status == "up"
    assert v2.allowaccess == ["ping", "ssh"]

    # Identical VLAN ID 100 in tenant-b with nested IPv6
    v3 = next(intf for intf in vlans if intf.name == "vlan100_tenant")
    assert v3.vdom == "tenant-b"
    assert v3.vlanid == 100
    assert v3.interface == "port1"
    assert v3.ip == "10.3.3.1 255.255.255.0"
    assert v3.ip6_address == "2001:db8:100::1/64"
    assert v3.ip6_allowaccess == ["ping", "https"]


def test_vlan_interface_malformed_values_preserved_safely() -> None:
    config = """
config system interface
    edit "vlan_bad"
        set type vlan
        set vlanid not_a_number
        set interface "port1" "port2"
    next
end
"""
    cfg = parse_fortigate_config(config)
    assert len(cfg.interfaces) == 1
    intf = cfg.interfaces[0]
    assert intf.vlanid is None
    assert intf.interface is None
    assert intf.source_attributes.get("unparsed_vlanid") == "not_a_number"
    assert intf.source_attributes.get("unparsed_interface") == "port1 port2"
