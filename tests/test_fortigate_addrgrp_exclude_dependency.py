from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _dependency(result, source_path, field, reference):
    return next(
        item
        for item in result.dependencies
        if item.source_path == source_path
        and item.source_field == field
        and item.reference == reference
    )


def test_ipv4_exclude_member_does_not_resolve_nested_group() -> None:
    result = extract_fortigate_config(
        """config firewall address
    edit "A1"
        set subnet 10.0.0.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "CHILD"
        set member "A1"
    next
    edit "PARENT"
        set member "A1"
        set exclude enable
        set exclude-member "CHILD"
    next
end
"""
    )

    dependency = _dependency(result, "firewall addrgrp", "exclude-member", "CHILD")
    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address"
    assert dependency.target_path is None


def test_ipv6_exclude_member_does_not_resolve_nested_group() -> None:
    result = extract_fortigate_config(
        """config firewall address6
    edit "A6"
        set ip6 2001:db8::1/128
    next
end
config firewall addrgrp6
    edit "CHILD6"
        set member "A6"
    next
    edit "PARENT6"
        set member "A6"
        set exclude enable
        set exclude-member "CHILD6"
    next
end
"""
    )

    dependency = _dependency(result, "firewall addrgrp6", "exclude-member", "CHILD6")
    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address6"
    assert dependency.target_path is None


def test_interface_parent_and_zone_members_require_actual_interfaces() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit "port1"
    next
    edit "VLAN10"
        set interface "PARENT_ZONE"
        set vlanid 10
    next
end
config system zone
    edit "PARENT_ZONE"
        set interface "port1"
    next
    edit "CHILD_ZONE"
        set interface "PARENT_ZONE"
    next
end
"""
    )

    vlan_parent = _dependency(result, "system interface", "interface", "PARENT_ZONE")
    assert vlan_parent.result == "UNRESOLVED"
    assert vlan_parent.target_path is None

    zone_member = _dependency(result, "system zone", "interface", "PARENT_ZONE")
    assert zone_member.result == "UNRESOLVED"
    assert zone_member.target_path is None


def test_ippool_interface_fields_do_not_resolve_system_zone() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit "port1"
    next
end
config system zone
    edit "WAN_ZONE"
        set interface "port1"
    next
end
config firewall ippool
    edit "POOL"
        set startip 198.51.100.10
        set endip 198.51.100.20
        set associated-interface "WAN_ZONE"
        set arp-intf "WAN_ZONE"
    next
end
"""
    )

    for field in ("associated-interface", "arp-intf"):
        dependency = _dependency(result, "firewall ippool", field, "WAN_ZONE")
        assert dependency.result == "UNRESOLVED"
        assert dependency.target_path is None


def test_central_snat_interfaces_resolve_system_and_sdwan_zones() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit "port1"
    next
end
config system zone
    edit "REGULAR_ZONE"
        set interface "port1"
    next
end
config system sdwan
    set status enable
    config zone
        edit "WAN_ZONE"
        next
    end
end
config firewall central-snat-map
    edit 1
        set srcintf "REGULAR_ZONE"
        set dstintf "WAN_ZONE"
        set orig-addr "all"
        set dst-addr "all"
    next
end
"""
    )

    regular_zone = _dependency(
        result,
        "firewall central-snat-map",
        "srcintf",
        "REGULAR_ZONE",
    )
    assert regular_zone.result == "RESOLVED"
    assert regular_zone.expected_type == "system interface"
    assert regular_zone.target_path == "system zone"

    sdwan_zone = _dependency(
        result,
        "firewall central-snat-map",
        "dstintf",
        "WAN_ZONE",
    )
    assert sdwan_zone.result == "RESOLVED"
    assert sdwan_zone.expected_type == "system interface"
    assert sdwan_zone.target_path == "system sdwan zone"
