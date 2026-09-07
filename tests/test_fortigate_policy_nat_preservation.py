from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _assert_dependency(result, source_path, field, reference, target_path):
    dependency = next(
        item
        for item in result.dependencies
        if item.source_path == source_path
        and item.source_field == field
        and item.reference == reference
    )
    assert dependency.result == "RESOLVED"
    assert dependency.target_path == target_path


def test_ping_serv_status_uses_exact_cli_name_and_integer_type() -> None:
    parsed = parse_fortigate_config(
        """config system interface
    edit "port1"
        set ping-serv-status 3
        config secondaryip
            edit 1
                set ip 192.0.2.1 255.255.255.0
                set ping-serv-status 4
            next
        end
    next
end
"""
    )

    interface = parsed.interfaces[0]
    assert interface.ping_serv_status == 3
    assert interface.secondary_ips[0].ping_serv_status == 4
    assert "ping_serv_status" in interface.source_explicit_fields
    assert interface.source_attributes["ping_serv_status"] == 3


def test_src_vip_filter_is_typed_and_preserved_in_vip_and_nat_ir() -> None:
    parsed = parse_fortigate_config(
        """config system interface
    edit "WAN"
        set ip 203.0.113.1 255.255.255.0
    next
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
end
config system zone
    edit "WAN"
        set interface "WAN"
    next
    edit "LAN"
        set interface "LAN"
    next
end
config firewall vip
    edit "WEB_VIP"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
        set extintf "WAN"
        set src-filter "TRUSTED_SOURCE"
        set src-vip-filter enable
    next
end
config firewall policy
    edit 10
        set srcintf "WAN"
        set dstintf "LAN"
        set srcaddr "all"
        set dstaddr "WEB_VIP"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
    )

    source_vip = parsed.vips[0]
    assert source_vip.src_vip_filter == "enable"

    ir = FGToIRTransformer(parsed).transform()
    virtual_ip = next(item for item in ir.virtual_ips if item.name == "WEB_VIP")
    assert virtual_ip.extra_settings["src_vip_filter"] == "enable"
    assert virtual_ip.requires_manual_review is True

    nat_rule = next(
        item for item in ir.nat_rules if item.source_vip_reference == "WEB_VIP"
    )
    assert nat_rule.source_extra_settings["src_vip_filter"] == "enable"
    assert nat_rule.requires_manual_review is True
    assert any("src-vip-filter" in reason for reason in nat_rule.review_reasons)


def test_firewall_policy_onetime_schedule_dependency_resolves() -> None:
    result = extract_fortigate_config(
        """config firewall schedule onetime
    edit "maintenance-window"
        set start "23:00 2026/09/10"
        set end "01:00 2026/09/11"
    next
end
config firewall policy
    edit 20
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "maintenance-window"
        set service "ALL"
    next
end
"""
    )

    _assert_dependency(
        result,
        "firewall policy",
        "schedule",
        "maintenance-window",
        "firewall schedule onetime",
    )


def test_preserved_group_relationships_are_dependency_resolved() -> None:
    result = extract_fortigate_config(
        """config firewall address
    edit "A1"
        set subnet 10.0.0.1 255.255.255.255
    next
    edit "A2"
        set subnet 10.0.0.2 255.255.255.255
    next
end
config firewall addrgrp
    edit "CHILD"
        set member "A1"
    next
    edit "PARENT"
        set member "CHILD" "A2"
        set exclude enable
        set exclude-member "A1"
    next
end
config firewall service custom
    edit "SVC1"
        set tcp-portrange 443
    next
end
config firewall service group
    edit "SVC_CHILD"
        set member "SVC1"
    next
    edit "SVC_PARENT"
        set member "SVC_CHILD" "SVC1"
    next
end
config firewall schedule recurring
    edit "BUSINESS"
        set day monday tuesday
        set start 08:00
        set end 18:00
    next
end
config firewall schedule onetime
    edit "CHANGE"
        set start "23:00 2026/09/10"
        set end "01:00 2026/09/11"
    next
end
config firewall schedule group
    edit "MAINT_GROUP"
        set member "BUSINESS" "CHANGE"
    next
end
config firewall vip
    edit "VIP1"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
    next
end
config firewall vipgrp
    edit "VIP_GROUP"
        set member "VIP1"
    next
end
config firewall policy
    edit 30
        set srcintf "any"
        set dstintf "any"
        set srcaddr "PARENT"
        set dstaddr "VIP_GROUP"
        set action accept
        set schedule "MAINT_GROUP"
        set service "SVC_PARENT"
    next
end
"""
    )

    expected = [
        ("firewall addrgrp", "member", "A1", "firewall address"),
        ("firewall addrgrp", "member", "CHILD", "firewall addrgrp"),
        ("firewall addrgrp", "exclude-member", "A1", "firewall address"),
        ("firewall service group", "member", "SVC1", "firewall service custom"),
        ("firewall service group", "member", "SVC_CHILD", "firewall service group"),
        ("firewall schedule group", "member", "BUSINESS", "firewall schedule recurring"),
        ("firewall schedule group", "member", "CHANGE", "firewall schedule onetime"),
        ("firewall vipgrp", "member", "VIP1", "firewall vip"),
        ("firewall policy", "schedule", "MAINT_GROUP", "firewall schedule group"),
    ]
    for source_path, field, reference, target_path in expected:
        _assert_dependency(result, source_path, field, reference, target_path)


def test_preserved_interface_and_pool_associations_are_dependency_resolved() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "WAN"
        set ip 203.0.113.1 255.255.255.0
    next
    edit "VLAN10"
        set interface "LAN"
        set vlanid 10
    next
end
config system zone
    edit "INSIDE"
        set interface "LAN" "VLAN10"
    next
end
config firewall address
    edit "IF_NET"
        set type interface-subnet
        set interface "LAN"
    next
    edit "HOST"
        set subnet 10.0.0.10 255.255.255.255
        set associated-interface "LAN"
    next
end
config firewall ippool
    edit "POOL4"
        set startip 198.51.100.10
        set endip 198.51.100.20
        set associated-interface "WAN"
        set arp-intf "WAN"
    next
end
config firewall vip
    edit "VIP1"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
    next
end
config firewall vipgrp
    edit "VIP_GROUP"
        set interface "WAN"
        set member "VIP1"
    next
end
"""
    )

    expected = [
        ("system interface", "interface", "LAN", "system interface"),
        ("system zone", "interface", "VLAN10", "system interface"),
        ("firewall address", "interface", "LAN", "system interface"),
        ("firewall address", "associated-interface", "LAN", "system interface"),
        ("firewall ippool", "associated-interface", "WAN", "system interface"),
        ("firewall ippool", "arp-intf", "WAN", "system interface"),
        ("firewall vipgrp", "interface", "WAN", "system interface"),
    ]
    for source_path, field, reference, target_path in expected:
        _assert_dependency(result, source_path, field, reference, target_path)


def test_policy_nat_and_central_snat_preserved_references_are_resolved() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit "LAN"
    next
    edit "WAN"
    next
end
config firewall address
    edit "SRC4"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "DST4"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "DST4_GROUP"
        set member "DST4"
    next
end
config firewall address6
    edit "SRC6"
        set ip6 2001:db8:1::/64
    next
    edit "DST6"
        set ip6 2001:db8:2::/64
    next
end
config firewall addrgrp6
    edit "DST6_GROUP"
        set member "DST6"
    next
end
config firewall ippool
    edit "POOL4"
        set startip 198.51.100.10
        set endip 198.51.100.20
    next
end
config firewall ippool6
    edit "POOL6"
        set startip 2001:db8:ffff::10
        set endip 2001:db8:ffff::20
    next
end
config firewall policy
    edit 40
        set srcintf "LAN"
        set dstintf "WAN"
        set srcaddr "SRC4"
        set dstaddr "DST4"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
        set ippool enable
        set poolname "POOL4"
        set poolname6 "POOL6"
        set pcp-poolname "POOL4"
    next
end
config firewall central-snat-map
    edit 1
        set srcintf "LAN"
        set dstintf "WAN"
        set orig-addr "SRC4"
        set dst-addr "DST4_GROUP"
        set nat-ippool "POOL4"
    next
    edit 2
        set srcintf "LAN"
        set dstintf "WAN"
        set orig-addr6 "SRC6"
        set dst-addr6 "DST6_GROUP"
        set nat-ippool6 "POOL6"
    next
end
"""
    )

    expected = [
        ("firewall policy", "poolname", "POOL4", "firewall ippool"),
        ("firewall policy", "poolname6", "POOL6", "firewall ippool6"),
        ("firewall policy", "pcp-poolname", "POOL4", "firewall ippool"),
        ("firewall central-snat-map", "srcintf", "LAN", "system interface"),
        ("firewall central-snat-map", "dstintf", "WAN", "system interface"),
        ("firewall central-snat-map", "orig-addr", "SRC4", "firewall address"),
        ("firewall central-snat-map", "dst-addr", "DST4_GROUP", "firewall addrgrp"),
        ("firewall central-snat-map", "nat-ippool", "POOL4", "firewall ippool"),
        ("firewall central-snat-map", "orig-addr6", "SRC6", "firewall address6"),
        ("firewall central-snat-map", "dst-addr6", "DST6_GROUP", "firewall addrgrp6"),
        ("firewall central-snat-map", "nat-ippool6", "POOL6", "firewall ippool6"),
    ]
    for source_path, field, reference, target_path in expected:
        _assert_dependency(result, source_path, field, reference, target_path)
