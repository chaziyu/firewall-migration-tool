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
