from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _inventory_item(result, source_path: str, source_id: str):
    return next(
        item
        for item in result.inventory_items
        if item.source_path == source_path and item.source_id == source_id
    )


def _commands(item):
    return [(command.operation, command.key, command.values) for command in item.commands]


def test_mixed_source_only_families_keep_status_provenance_and_generation_boundary():
    result = extract_fortigate_config(
        '''config router policy
    edit 10
        set input-device "port3" "port1"
        set src "10.30.0.0/24" "10.10.0.0/24"
        set dst "203.0.113.0/24" "198.51.100.0/24"
        set srcaddr "SRC-B" "SRC-A"
        set dstaddr "DST-B" "DST-A"
        set gateway 192.0.2.1
        set output-device "wan"
    next
end
config router policy6
    edit 20
        set status disable
        set input-device "port6" "port5"
        set src "2001:db8:30::/64" "2001:db8:10::/64"
        set dst "2001:db8:300::/64" "2001:db8:100::/64"
        set gateway 2001:db8::1
        set output-device "wan6"
    next
end
config firewall local-in-policy
    edit 30
        set intf "wan3" "wan1"
        set srcaddr "ADMIN-B" "ADMIN-A"
        set dstaddr "FGT-B" "FGT-A"
        set service "HTTPS" "SSH"
        set action accept
        set schedule "always"
    next
end
config firewall local-in-policy6
    edit 40
        set status enable
        set intf "wan6" "wan5"
        set srcaddr "ADMIN6-B" "ADMIN6-A"
        set dstaddr "FGT6-B" "FGT6-A"
        set service "HTTPS" "SSH"
        set action accept
        set schedule "always"
    next
end
'''
    )

    ir = result.canonical_ir
    assert [(rule.family, rule.source_id, rule.enabled) for rule in ir.policy_routes] == [
        ("policy-route-ipv4", "10", True),
        ("policy-route-ipv6", "20", False),
    ]
    assert [(rule.family, rule.source_id, rule.enabled) for rule in ir.local_in_policies] == [
        ("local-in-policy-ipv4", "30", True),
        ("local-in-policy-ipv6", "40", True),
    ]
    assert [rule.effective_action for rule in ir.policy_routes] == ["permit", "permit"]
    assert [rule.effective_action for rule in ir.local_in_policies] == ["accept", "accept"]
    assert ir.routes == []
    assert ir.policies == []
    assert ir.nat_rules == []
    assert result.generation_safe is False
    assert result.migration_complete is False

    pbr4 = ir.policy_routes[0].source_attributes
    assert pbr4["input_device"] == ["port3", "port1"]
    assert pbr4["src"] == ["10.30.0.0/24", "10.10.0.0/24"]
    assert pbr4["srcaddr"] == ["SRC-B", "SRC-A"]
    assert "status" not in pbr4
    assert ir.policy_routes[1].source_attributes["status"] == "disable"

    local4 = ir.local_in_policies[0].source_attributes
    assert local4["intf"] == ["wan3", "wan1"]
    assert local4["srcaddr"] == ["ADMIN-B", "ADMIN-A"]
    assert "status" not in local4
    assert ir.local_in_policies[1].source_attributes["status"] == "enable"

    pbr4_item = _inventory_item(result, "router policy", "10")
    local4_item = _inventory_item(result, "firewall local-in-policy", "30")
    assert _commands(pbr4_item) == [
        ("set", "input-device", ["port3", "port1"]),
        ("set", "src", ["10.30.0.0/24", "10.10.0.0/24"]),
        ("set", "dst", ["203.0.113.0/24", "198.51.100.0/24"]),
        ("set", "srcaddr", ["SRC-B", "SRC-A"]),
        ("set", "dstaddr", ["DST-B", "DST-A"]),
        ("set", "gateway", ["192.0.2.1"]),
        ("set", "output-device", ["wan"]),
    ]
    assert all(command[1] != "status" for command in _commands(local4_item))

    dumped = result.model_dump()
    assert dumped["canonical_ir"]["policy_routes"][0]["source_attributes"]["src"] == [
        "10.30.0.0/24",
        "10.10.0.0/24",
    ]
    assert dumped["canonical_ir"]["local_in_policies"][0]["source_attributes"]["service"] == [
        "HTTPS",
        "SSH",
    ]

    for family in (
        "policy-route-ipv4",
        "policy-route-ipv6",
        "local-in-policy-ipv4",
        "local-in-policy-ipv6",
    ):
        assert any(f"{family} " in reason for reason in result.blocking_reasons)


def test_ipv6_policy_dependencies_and_explicit_field_typing_share_public_pipeline():
    result = extract_fortigate_config(
        '''config system interface
    edit "lan"
    next
    edit "dmz"
    next
    edit "wan"
    next
    edit "port3"
    next
end
config firewall address6
    edit "SRC6"
        set ip6 2001:db8:10::/64
    next
    edit "DST6"
        set ip6 2001:db8:20::/64
    next
end
config firewall addrgrp6
    edit "SRC6-GROUP"
        set member "SRC6"
    next
    edit "DST6-GROUP"
        set member "DST6"
    next
end
config firewall policy
    edit 1
        set srcintf "dmz" "lan"
        set dstintf "wan" "port3"
        set srcaddr "all" "none"
        set dstaddr "all"
        set srcaddr6 "SRC6" "SRC6-GROUP"
        set dstaddr6 "DST6" "DST6-GROUP"
        set service "ALL" "ALL"
        set groups "all" "none"
        set users "all" "none"
        set poolname "POOL-B" "POOL-A"
        set poolname6 "POOL6-B" "POOL6-A"
        set fsso-groups "FSSO-B" "FSSO-A"
        set internet-service-custom "IS-B" "IS-A"
        set internet-service-src-custom "ISS-B" "ISS-A"
        set internet-service6-custom "IS6-B" "IS6-A"
        set internet-service6-src-custom "ISS6-B" "ISS6-A"
        set ztna-ems-tag "TAG-B" "TAG-A"
        set action accept
        set status enable
        set schedule "always"
        set comments "typed policy"
        set future-traffic-setting "first" "second"
    next
end
'''
    )

    policy = result.canonical_ir.policies[0]
    assert policy.source_from_interfaces == ["dmz", "lan"]
    assert policy.source_to_interfaces == ["wan", "port3"]
    assert policy.source_address_references == ["all", "none"]
    assert policy.destination_address_references == ["all"]
    assert policy.source_ipv6_address_references == ["SRC6", "SRC6-GROUP"]
    assert policy.destination_ipv6_address_references == ["DST6", "DST6-GROUP"]
    assert policy.source_service_references == ["ALL", "ALL"]
    assert policy.source_user_groups == ["all", "none"]
    assert policy.source_users == ["all", "none"]
    assert policy.nat_pool_names == ["POOL-B", "POOL-A"]
    assert policy.nat_pool_names6 == ["POOL6-B", "POOL6-A"]
    assert policy.source_ztna_ems_tags == ["TAG-B", "TAG-A"]
    assert policy.source_internet_service_settings == {
        "internet-service-custom": ["IS-B", "IS-A"],
        "internet-service-src-custom": ["ISS-B", "ISS-A"],
        "internet-service6-custom": ["IS6-B", "IS6-A"],
        "internet-service6-src-custom": ["ISS6-B", "ISS6-A"],
    }
    assert policy.source_extra_settings["future_traffic_setting"] == "first second"

    ipv6_dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field in {"srcaddr6", "dstaddr6"}
    ]
    assert [
        (dependency.source_field, dependency.reference, dependency.result, dependency.target_path)
        for dependency in ipv6_dependencies
    ] == [
        ("srcaddr6", "SRC6", "RESOLVED", "firewall address6"),
        ("srcaddr6", "SRC6-GROUP", "RESOLVED", "firewall addrgrp6"),
        ("dstaddr6", "DST6", "RESOLVED", "firewall address6"),
        ("dstaddr6", "DST6-GROUP", "RESOLVED", "firewall addrgrp6"),
    ]
    assert not any(
        "srcaddr6" in reason or "dstaddr6" in reason
        for reason in result.blocking_reasons
        if "Unresolved FortiGate reference" in reason
    )

    policy_item = _inventory_item(result, "firewall policy", "1")
    future_command = next(command for command in policy_item.commands if command.key == "future-traffic-setting")
    assert future_command.values == ["first", "second"]
    assert policy_item.requires_manual_review is True


def test_ipv6_dependency_failures_retain_restrictions_and_block_without_fallback():
    result = extract_fortigate_config(
        '''config system interface
    edit "lan"
    next
    edit "wan"
    next
end
config firewall address
    edit "SAME-NAME"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config firewall vip6
    edit "VIP6-NAME"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set srcaddr6 "SAME-NAME" "MISSING-SRC6"
        set dstaddr6 "VIP6-NAME" "MISSING-DST6"
        set service "ALL"
        set action accept
        set schedule "always"
    next
end
'''
    )

    policy = result.canonical_ir.policies[0]
    assert policy.source_ipv6_address_references == ["SAME-NAME", "MISSING-SRC6"]
    assert policy.destination_ipv6_address_references == ["VIP6-NAME", "MISSING-DST6"]
    ipv6_dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field in {"srcaddr6", "dstaddr6"}
    ]
    assert [dependency.reference for dependency in ipv6_dependencies] == [
        "SAME-NAME",
        "MISSING-SRC6",
        "VIP6-NAME",
        "MISSING-DST6",
    ]
    assert all(
        dependency.result == "UNRESOLVED"
        and dependency.expected_type == "firewall address6"
        and dependency.target_path is None
        for dependency in ipv6_dependencies
    )
    assert "all" not in policy.source_ipv6_address_references
    assert result.generation_safe is False
    assert result.migration_complete is False

    section = next(section for section in result.source_sections if section.path == "firewall policy")
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert section.unresolved_dependencies == 4
    item = _inventory_item(result, "firewall policy", "1")
    assert item.requires_manual_review is True
    assert {"unresolved-reference:SAME-NAME", "unresolved-reference:MISSING-SRC6",
            "unresolved-reference:VIP6-NAME", "unresolved-reference:MISSING-DST6"} <= set(item.notes)
    assert len([
        entry for entry in result.canonical_ir.audit_entries
        if entry.category == "FortiGate Dependency"
    ]) == 4
    assert all(
        any(reference in reason for reason in result.blocking_reasons)
        for reference in ("SAME-NAME", "MISSING-SRC6", "VIP6-NAME", "MISSING-DST6")
    )


def test_ipv6_policy_dependency_resolution_remains_vdom_scoped_end_to_end():
    result = extract_fortigate_config(
        '''config vdom
edit root
    config firewall address6
        edit "SHARED6"
            set ip6 2001:db8::/64
        next
    end
next
edit tenant-a
    config firewall policy
        edit 1
            set srcintf "any"
            set dstintf "any"
            set srcaddr "all"
            set dstaddr "all"
            set srcaddr6 "SHARED6"
            set dstaddr6 "SHARED6"
            set service "ALL"
            set action accept
        next
    end
next
end
'''
    )

    policy = result.canonical_ir.policies[0]
    assert policy.source_context == "tenant-a"
    ipv6_dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field in {"srcaddr6", "dstaddr6"}
    ]
    assert [(dependency.source_context, dependency.reference, dependency.result)
            for dependency in ipv6_dependencies] == [
        ("tenant-a", "SHARED6", "UNRESOLVED"),
        ("tenant-a", "SHARED6", "UNRESOLVED"),
    ]
    assert all(dependency.target_path is None for dependency in ipv6_dependencies)
