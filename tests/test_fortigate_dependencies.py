import pytest

from fwmigrate.extraction.models import (
    DependencyRecord,
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
)
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _item(
    source_path: str,
    name: str,
    *,
    context: str = "root",
    commands: list[tuple[str, list[str]]] | None = None,
) -> SourceInventoryItem:
    return SourceInventoryItem(
        domain=source_path.split(" ", 1)[0],
        source_path=source_path,
        name=name,
        source_context=context,
        commands=[
            SourceCommand(operation="set", key=field, values=values)
            for field, values in (commands or [])
        ],
    )


def test_vip_literal_ips_do_not_create_address_dependencies() -> None:
    result = extract_fortigate_config(
        """config firewall vip
    edit "WEB-VIP"
        set extip 198.51.100.10
        set mappedip 10.10.10.10 10.10.10.20
    next
end
"""
    )

    assert not [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall vip"
        and dependency.source_object == "WEB-VIP"
        and dependency.source_field in {"extip", "mappedip"}
    ]


def test_vip_address_object_dependencies_are_strict_and_resolved() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall address", "PUBLIC-HOST"),
            _item("firewall address", "BACKEND-HOST"),
            _item(
                "firewall vip",
                "WEB-VIP",
                commands=[
                    ("extip", ["203.0.113.10"]),
                    ("extaddr", ["PUBLIC-HOST"]),
                    ("mapped-addr", ["BACKEND-HOST"]),
                ],
            ),
        ]
    )

    assert [(dependency.source_field, dependency.reference, dependency.result, dependency.target_path) for dependency in dependencies] == [
        ("extaddr", "PUBLIC-HOST", "RESOLVED", "firewall address"),
        ("mapped-addr", "BACKEND-HOST", "RESOLVED", "firewall address"),
    ]


def test_missing_vip_address_object_dependency_remains_unresolved() -> None:
    dependency = build_dependency_registry(
        [_item("firewall vip", "WEB-VIP", commands=[("extaddr", ["MISSING-PUBLIC-HOST"])])]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


@pytest.mark.parametrize(
    ("field", "target_path", "reference", "result"),
    [
        ("service", "firewall service custom", "APP_8443", "RESOLVED"),
        ("service", "firewall service group", "APP_8443", "RESOLVED"),
        ("service", "firewall service custom", "MISSING_SERVICE", "UNRESOLVED"),
        ("monitor", "firewall ldb-monitor", "HTTP_HEALTH", "RESOLVED"),
        ("monitor", "firewall ldb-monitor", "MISSING_MONITOR", "UNRESOLVED"),
    ],
)
def test_vip_service_and_monitor_dependencies(
    field: str, target_path: str, reference: str, result: str
) -> None:
    dependencies = build_dependency_registry([
        _item(target_path, reference) if result == "RESOLVED" else _item(target_path, "other"),
        _item("firewall vip", "VIP_APP", commands=[(field, [reference])]),
    ])

    assert dependencies[0].result == result
    assert dependencies[0].target_path == (target_path if result == "RESOLVED" else None)


def test_vip_realserver_dependencies_are_type_aware_and_vdom_scoped() -> None:
    dependencies = build_dependency_registry([
        _item("firewall address", "APP01", context="VDOM_A"),
        _item("firewall address", "APP02", context="VDOM_B"),
        _item("firewall ldb-monitor", "TCP_MON", context="VDOM_B"),
        _item(
            "firewall vip realservers", "1", context="VDOM_B",
            commands=[("type", ["address"]), ("address", ["APP01"]), ("monitor", ["TCP_MON"])],
        ),
        _item(
            "firewall vip realservers", "2", context="VDOM_B",
            commands=[("type", ["ip"]), ("address", ["APP02"]), ("ip", ["10.0.0.20"]), ("monitor", ["MISSING_MONITOR"])],
        ),
        _item(
            "firewall vip realservers", "3", context="VDOM_B",
            commands=[("type", ["address"]), ("address", ["MISSING_APP"])],
        ),
    ])

    assert [(dependency.source_object, dependency.source_field, dependency.reference, dependency.result) for dependency in dependencies] == [
        ("1", "address", "APP01", "UNRESOLVED"),
        ("1", "monitor", "TCP_MON", "RESOLVED"),
        ("2", "monitor", "MISSING_MONITOR", "UNRESOLVED"),
        ("3", "address", "MISSING_APP", "UNRESOLVED"),
    ]


def test_vip_realserver_address_dependency_resolves_from_cli_text() -> None:
    result = extract_fortigate_config(
        """config firewall address
    edit "APP01"
        set subnet 10.0.0.10 255.255.255.255
    next
end
config firewall vip
    edit "VIP_APP"
        config realservers
            edit 1
                set type address
                set address "APP01"
            next
            edit 2
                set type ip
                set ip 10.0.0.20
            next
        end
    next
end
"""
    )

    dependencies = [dependency for dependency in result.dependencies if dependency.source_path == "firewall vip realservers"]
    assert [(dependency.source_object, dependency.source_field, dependency.reference, dependency.result) for dependency in dependencies] == [
        ("1", "address", "APP01", "RESOLVED"),
    ]


@pytest.mark.parametrize(
    ("source_path", "field", "target_path", "expected_type"),
    [
        ("router policy", "input-device", "system interface", "system interface"),
        ("router policy", "output-device", "system interface", "system interface"),
        ("router policy", "srcaddr", "firewall address", "firewall address"),
        ("router policy", "srcaddr", "firewall addrgrp", "firewall address"),
        ("router policy", "dstaddr", "firewall address", "firewall address"),
        ("router policy", "dstaddr", "firewall addrgrp", "firewall address"),
        (
            "router policy",
            "internet-service-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
        ("router policy6", "input-device", "system interface", "system interface"),
        ("router policy6", "output-device", "system interface", "system interface"),
        ("router policy6", "srcaddr", "firewall address6", "firewall address6"),
        ("router policy6", "srcaddr", "firewall addrgrp6", "firewall address6"),
        ("router policy6", "dstaddr", "firewall address6", "firewall address6"),
        ("router policy6", "dstaddr", "firewall addrgrp6", "firewall address6"),
        (
            "router policy6",
            "internet-service-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
    ],
)
def test_source_only_pbr_dependency_target_matrix(
    source_path: str,
    field: str,
    target_path: str,
    expected_type: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "target"),
            _item(source_path, "rule-1", commands=[(field, ["target"])]),
        ]
    )[0]

    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == expected_type
    assert dependency.target_path == target_path


@pytest.mark.parametrize(
    ("source_path", "field", "target_path", "expected_type"),
    [
        ("firewall local-in-policy", "intf", "system interface", "system interface"),
        ("firewall local-in-policy", "srcaddr", "firewall address", "firewall address"),
        ("firewall local-in-policy", "srcaddr", "firewall addrgrp", "firewall address"),
        ("firewall local-in-policy", "dstaddr", "firewall address", "firewall address"),
        ("firewall local-in-policy", "dstaddr", "firewall addrgrp", "firewall address"),
        ("firewall local-in-policy", "service", "firewall service custom", "firewall service custom"),
        ("firewall local-in-policy", "service", "firewall service group", "firewall service custom"),
        ("firewall local-in-policy", "schedule", "firewall schedule recurring", "firewall schedule recurring"),
        ("firewall local-in-policy", "schedule", "firewall schedule onetime", "firewall schedule recurring"),
        ("firewall local-in-policy", "schedule", "firewall schedule group", "firewall schedule recurring"),
        (
            "firewall local-in-policy",
            "internet-service-src-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
        (
            "firewall local-in-policy",
            "internet-service-src-custom-group",
            "firewall internet-service-custom-group",
            "firewall internet-service-custom-group",
        ),
        (
            "firewall local-in-policy",
            "internet-service-src-group",
            "firewall internet-service-group",
            "firewall internet-service-group",
        ),
        ("firewall local-in-policy6", "intf", "system interface", "system interface"),
        ("firewall local-in-policy6", "srcaddr", "firewall address6", "firewall address6"),
        ("firewall local-in-policy6", "srcaddr", "firewall addrgrp6", "firewall address6"),
        ("firewall local-in-policy6", "dstaddr", "firewall address6", "firewall address6"),
        ("firewall local-in-policy6", "dstaddr", "firewall addrgrp6", "firewall address6"),
        ("firewall local-in-policy6", "service", "firewall service custom", "firewall service custom"),
        ("firewall local-in-policy6", "service", "firewall service group", "firewall service custom"),
        ("firewall local-in-policy6", "schedule", "firewall schedule recurring", "firewall schedule recurring"),
        ("firewall local-in-policy6", "schedule", "firewall schedule onetime", "firewall schedule recurring"),
        ("firewall local-in-policy6", "schedule", "firewall schedule group", "firewall schedule recurring"),
        (
            "firewall local-in-policy6",
            "internet-service6-src-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
        (
            "firewall local-in-policy6",
            "internet-service6-src-custom-group",
            "firewall internet-service-custom-group",
            "firewall internet-service-custom-group",
        ),
        (
            "firewall local-in-policy6",
            "internet-service6-src-group",
            "firewall internet-service-group",
            "firewall internet-service-group",
        ),
    ],
)
def test_source_only_local_in_dependency_target_matrix(
    source_path: str,
    field: str,
    target_path: str,
    expected_type: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "target"),
            _item(source_path, "rule-1", commands=[(field, ["target"])]),
        ]
    )[0]

    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == expected_type
    assert dependency.target_path == target_path


@pytest.mark.parametrize(
    ("source_path", "field", "target_path"),
    [
        ("router policy", "srcaddr", "firewall address6"),
        ("router policy", "dstaddr", "firewall addrgrp6"),
        ("router policy", "input-device", "system zone"),
        ("router policy", "output-device", "system sdwan zone"),
        ("router policy", "internet-service-custom", "firewall internet-service-custom-group"),
        ("router policy", "internet-service-custom", "firewall internet-service-name"),
        ("router policy6", "srcaddr", "firewall address"),
        ("router policy6", "dstaddr", "firewall addrgrp"),
        ("router policy6", "input-device", "system zone"),
        ("router policy6", "output-device", "system sdwan zone"),
        ("firewall local-in-policy", "srcaddr", "firewall address6"),
        ("firewall local-in-policy", "dstaddr", "firewall vip"),
        ("firewall local-in-policy", "service", "firewall address"),
        ("firewall local-in-policy6", "srcaddr", "firewall address"),
        ("firewall local-in-policy6", "dstaddr", "firewall vip6"),
        ("firewall local-in-policy6", "service", "firewall address"),
    ],
)
def test_source_only_dependencies_reject_wrong_target_families(
    source_path: str,
    field: str,
    target_path: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "same-name"),
            _item(source_path, "rule-1", commands=[(field, ["same-name"])]),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


@pytest.mark.parametrize(
    ("source_path", "field"),
    [
        ("router policy", "input-device"),
        ("router policy", "output-device"),
        ("router policy", "srcaddr"),
        ("router policy", "dstaddr"),
        ("router policy", "internet-service-custom"),
        ("router policy6", "input-device"),
        ("router policy6", "srcaddr"),
        ("firewall local-in-policy", "intf"),
        ("firewall local-in-policy", "srcaddr"),
        ("firewall local-in-policy", "service"),
        ("firewall local-in-policy", "schedule"),
        ("firewall local-in-policy6", "intf"),
        ("firewall local-in-policy6", "dstaddr"),
        ("firewall local-in-policy6", "service"),
    ],
)
def test_source_only_missing_dependencies_are_unresolved(
    source_path: str,
    field: str,
) -> None:
    dependency = build_dependency_registry(
        [_item(source_path, "rule-1", commands=[(field, ["missing"])]),]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_source_only_dependency_values_preserve_order_and_granularity() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system interface", "port1"),
            _item("system interface", "port2"),
            _item("firewall address", "SRC-A"),
            _item("firewall addrgrp", "SRC-GRP"),
            _item(
                "router policy",
                "rule-1",
                commands=[
                    ("input-device", ["port2", "port1", "missing-port"]),
                    ("srcaddr", ["SRC-A", "SRC-GRP", "MISSING-SRC"]),
                ],
            ),
        ]
    )

    assert [(d.source_field, d.reference, d.result) for d in dependencies] == [
        ("input-device", "port2", "RESOLVED"),
        ("input-device", "port1", "RESOLVED"),
        ("input-device", "missing-port", "UNRESOLVED"),
        ("srcaddr", "SRC-A", "RESOLVED"),
        ("srcaddr", "SRC-GRP", "RESOLVED"),
        ("srcaddr", "MISSING-SRC", "UNRESOLVED"),
    ]


def test_source_only_dependencies_remain_vdom_scoped() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system interface", "port1", context="root"),
            _item("firewall address", "SRC-A", context="root"),
            _item(
                "router policy",
                "rule-1",
                context="tenant-a",
                commands=[
                    ("input-device", ["port1"]),
                    ("srcaddr", ["SRC-A"]),
                ],
            ),
        ]
    )

    assert [(d.reference, d.result, d.target_path) for d in dependencies] == [
        ("port1", "UNRESOLVED", None),
        ("SRC-A", "UNRESOLVED", None),
    ]


def test_source_only_literals_are_ignored_but_database_ids_are_external() -> None:
    dependencies = build_dependency_registry(
        [
            _item(
                "router policy",
                "rule-1",
                commands=[
                    ("src", ["10.0.0.0/24"]),
                    ("dst", ["2001:db8::/64"]),
                    ("gateway", ["192.0.2.1"]),
                    ("internet-service-id", ["65646"]),
                ],
            ),
            _item(
                "router policy6",
                "rule-2",
                commands=[
                    ("src", ["2001:db8::/64"]),
                    ("dst", ["::/0"]),
                    ("gateway", ["2001:db8::1"]),
                    ("internet-service-id", ["70001"]),
                ],
            ),
        ]
    )

    assert [
        (dependency.source_path, dependency.reference, dependency.result)
        for dependency in dependencies
    ] == [
        ("router policy", "65646", "EXTERNAL"),
        ("router policy6", "70001", "EXTERNAL"),
    ]
    assert all(dependency.target_path is None for dependency in dependencies)


def test_local_in_builtins_are_filtered_by_generic_dependency_handling() -> None:
    dependencies = build_dependency_registry(
        [
            _item(
                "firewall local-in-policy",
                "rule-1",
                commands=[
                    ("intf", ["any"]),
                    ("dstaddr", ["all"]),
                    ("service", ["ALL"]),
                    ("schedule", ["always"]),
                ],
            ),
        ]
    )

    assert dependencies == []


def test_source_only_dependency_propagation_is_generic() -> None:
    result = extract_fortigate_config(
        """config router policy
    edit 1
        set input-device "missing-port"
        set src "10.0.0.0/24"
        set dst "0.0.0.0/0"
        set srcaddr "missing-src"
        set gateway 192.0.2.1
        set output-device "missing-wan"
        set internet-service-id 65646
    next
end
"""
    )

    unresolved = [
        dependency for dependency in result.dependencies
        if dependency.source_path == "router policy"
        and dependency.result == "UNRESOLVED"
    ]
    assert [dependency.source_field for dependency in unresolved] == [
        "input-device",
        "srcaddr",
        "output-device",
    ]
    assert all(dependency.result == "UNRESOLVED" for dependency in unresolved)
    assert [
        dependency.result
        for dependency in result.dependencies
        if dependency.source_field == "internet-service-id"
    ] == ["EXTERNAL"]
    assert result.generation_safe is False
    assert any("missing-src" in reason for reason in result.blocking_reasons)
    assert any("missing-port" in note for item in result.inventory_items for note in item.notes)


@pytest.mark.parametrize(
    ("field", "target_path", "expected_type"),
    [
        ("srcintf", "system interface", "system interface"),
        ("dstintf", "system interface", "system interface"),
        ("srcintf", "system zone", "system interface"),
        ("dstintf", "system zone", "system interface"),
        ("srcintf", "system sdwan zone", "system interface"),
        ("dstintf", "system sdwan zone", "system interface"),
        ("srcaddr", "firewall address", "firewall address"),
        ("srcaddr", "firewall addrgrp", "firewall address"),
        ("dstaddr", "firewall address", "firewall address"),
        ("dstaddr", "firewall addrgrp", "firewall address"),
        ("dstaddr", "firewall vip", "firewall address"),
        ("dstaddr", "firewall vipgrp", "firewall address"),
        ("srcaddr6", "firewall address6", "firewall address6"),
        ("srcaddr6", "firewall addrgrp6", "firewall address6"),
        ("dstaddr6", "firewall address6", "firewall address6"),
        ("dstaddr6", "firewall addrgrp6", "firewall address6"),
    ],
)
def test_policy_dependency_target_sections_are_field_specific(
    field: str,
    target_path: str,
    expected_type: str,
) -> None:
    dependencies = build_dependency_registry(
        [
            _item(target_path, "target"),
            _item(
                "firewall policy",
                "policy-1",
                commands=[(field, ["target"])],
            ),
        ]
    )

    assert len(dependencies) == 1
    dependency = dependencies[0]
    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == expected_type
    assert dependency.target_path == target_path


@pytest.mark.parametrize("target_path", ["firewall vip", "firewall vipgrp"])
def test_policy_source_addresses_do_not_resolve_vips_or_vip_groups(
    target_path: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "published-object"),
            _item(
                "firewall policy",
                "policy-1",
                commands=[("srcaddr", ["published-object"])],
            ),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address"
    assert dependency.target_path is None


@pytest.mark.parametrize(
    ("field", "reference"),
    [
        ("srcintf", "missing-sdwan-zone"),
        ("dstaddr", "missing-vip"),
        ("dstaddr", "missing-vip-group"),
        ("srcaddr6", "missing-src6"),
        ("dstaddr6", "missing-dst6"),
    ],
)
def test_missing_policy_references_remain_unresolved(
    field: str,
    reference: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(
                "firewall policy",
                "policy-1",
                commands=[(field, [reference])],
            ),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_policy_references_do_not_cross_vdom_contexts() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system sdwan zone", "shared-zone", context="root"),
            _item("firewall vip", "shared-vip", context="root"),
            _item("firewall address6", "shared6", context="root"),
            _item(
                "firewall policy",
                "policy-1",
                context="tenant-a",
                commands=[
                    ("dstintf", ["shared-zone"]),
                    ("dstaddr", ["shared-vip"]),
                    ("srcaddr6", ["shared6"]),
                    ("dstaddr6", ["shared6"]),
                ],
            ),
        ]
    )

    assert [(dependency.reference, dependency.result) for dependency in dependencies] == [
        ("shared-zone", "UNRESOLVED"),
        ("shared-vip", "UNRESOLVED"),
        ("shared6", "UNRESOLVED"),
        ("shared6", "UNRESOLVED"),
    ]


@pytest.mark.parametrize("field", ["srcaddr6", "dstaddr6"])
@pytest.mark.parametrize(
    "target_path",
    ["firewall address", "firewall addrgrp"],
)
def test_ipv6_policy_addresses_do_not_resolve_ipv4_objects(
    field: str,
    target_path: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "shared-name"),
            _item(
                "firewall policy",
                "policy-1",
                commands=[(field, ["shared-name"])],
            ),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address6"
    assert dependency.target_path is None


@pytest.mark.parametrize("field", ["srcaddr6", "dstaddr6"])
@pytest.mark.parametrize(
    "target_path",
    ["firewall vip", "firewall vipgrp", "firewall vip6", "firewall vipgrp6"],
)
def test_ipv6_policy_addresses_do_not_resolve_vip_families(
    field: str,
    target_path: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "published-object"),
            _item(
                "firewall policy",
                "policy-1",
                commands=[(field, ["published-object"])],
            ),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address6"
    assert dependency.target_path is None


def test_ipv6_policy_multi_value_dependencies_filter_builtins_and_preserve_order() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall address6", "SRC6-A"),
            _item("firewall addrgrp6", "SRC6-GROUP"),
            _item(
                "firewall policy",
                "policy-1",
                commands=[
                    ("srcaddr6", ["SRC6-A", "SRC6-GROUP", "MISSING-SRC6", "all"]),
                ],
            ),
        ]
    )

    assert [dependency.reference for dependency in dependencies] == [
        "SRC6-A",
        "SRC6-GROUP",
        "MISSING-SRC6",
    ]
    assert [(dependency.result, dependency.target_path) for dependency in dependencies] == [
        ("RESOLVED", "firewall address6"),
        ("RESOLVED", "firewall addrgrp6"),
        ("UNRESOLVED", None),
    ]
    assert all(dependency.expected_type == "firewall address6" for dependency in dependencies)


@pytest.mark.parametrize(
    ("source_path", "field"),
    [
        ("router static", "device"),
        ("system link-monitor", "srcintf"),
        ("firewall vip", "extintf"),
    ],
)
def test_sdwan_zones_are_not_added_to_global_interface_aliases(
    source_path: str,
    field: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item("system sdwan zone", "virtual-wan-link"),
            _item(source_path, "source-object", commands=[(field, ["virtual-wan-link"])]),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"


def test_user_dependency_keeps_legacy_prefix_matching() -> None:
    dependency = build_dependency_registry(
        [
            _item("user radius", "radius1"),
            _item(
                "user group",
                "vpn-users",
                commands=[("member", ["radius1"])],
            ),
        ]
    )[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "user radius"


def _policy_dependencies(content: str) -> dict[tuple[str, str], DependencyRecord]:
    result = extract_fortigate_config(content)
    return {
        (dependency.source_field, dependency.reference): dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
    }


def test_extraction_resolves_sdwan_zone_and_vip_destination_from_cli_text() -> None:
    content_template = """config system interface
    edit \"LAN\"
    next
end
config system sdwan
    config zone
        edit \"virtual-wan-link\"
        next
    end
end
config firewall vip
    edit \"WEB-VIP\"
        set extip 203.0.113.10
        set mappedip \"10.0.0.10\"
    next
end
config firewall vipgrp
    edit \"WEB-VIPS\"
        set member \"WEB-VIP\"
    next
end
config firewall policy
    edit 1
        set srcintf \"LAN\"
        set dstintf \"virtual-wan-link\"
        set srcaddr \"all\"
        set dstaddr \"{destination}\"
        set action accept
        set service \"ALL\"
        set schedule \"always\"
    next
end
"""

    vip_dependencies = _policy_dependencies(content_template.format(destination="WEB-VIP"))
    assert vip_dependencies[("dstintf", "virtual-wan-link")].result == "RESOLVED"
    assert vip_dependencies[("dstintf", "virtual-wan-link")].target_path == "system sdwan zone"
    assert vip_dependencies[("dstaddr", "WEB-VIP")].result == "RESOLVED"
    assert vip_dependencies[("dstaddr", "WEB-VIP")].target_path == "firewall vip"

    vip_group_dependencies = _policy_dependencies(
        content_template.format(destination="WEB-VIPS")
    )
    assert vip_group_dependencies[("dstaddr", "WEB-VIPS")].result == "RESOLVED"
    assert vip_group_dependencies[("dstaddr", "WEB-VIPS")].target_path == "firewall vipgrp"


def test_extraction_resolves_ipv6_policy_address_groups_from_cli_text() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit "lan"
    next
    edit "wan"
    next
end
config firewall address6
    edit "SRC6-HOST"
        set ip6 2001:db8:10::/64
    next
    edit "DST6-HOST"
        set ip6 2001:db8:20::/64
    next
end
config firewall addrgrp6
    edit "SRC6-GROUP"
        set member "SRC6-HOST"
    next
    edit "DST6-GROUP"
        set member "DST6-HOST"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set srcaddr6 "SRC6-GROUP"
        set dstaddr6 "DST6-GROUP"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
    )

    ipv6_dependencies = {
        dependency.source_field: dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field in {"srcaddr6", "dstaddr6"}
    }
    assert {
        field: (dependency.result, dependency.expected_type, dependency.target_path)
        for field, dependency in ipv6_dependencies.items()
    } == {
        "srcaddr6": ("RESOLVED", "firewall address6", "firewall addrgrp6"),
        "dstaddr6": ("RESOLVED", "firewall address6", "firewall addrgrp6"),
    }
    assert not any(
        "srcaddr6" in reason or "dstaddr6" in reason
        for reason in result.blocking_reasons
        if "Unresolved FortiGate reference" in reason
    )


def test_unresolved_ipv6_policy_references_propagate_through_extraction() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit "lan"
    next
    edit "wan"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set srcaddr6 "MISSING-SRC6"
        set dstaddr6 "MISSING-DST6"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
    )

    unresolved = {
        dependency.source_field: dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field in {"srcaddr6", "dstaddr6"}
    }
    assert {
        field: (
            dependency.source_path,
            dependency.reference,
            dependency.expected_type,
            dependency.result,
            dependency.target_path,
        )
        for field, dependency in unresolved.items()
    } == {
        "srcaddr6": (
            "firewall policy",
            "MISSING-SRC6",
            "firewall address6",
            "UNRESOLVED",
            None,
        ),
        "dstaddr6": (
            "firewall policy",
            "MISSING-DST6",
            "firewall address6",
            "UNRESOLVED",
            None,
        ),
    }

    assert result.generation_safe is False
    assert result.migration_complete is False
    assert any("MISSING-SRC6" in reason for reason in result.blocking_reasons)
    assert any("MISSING-DST6" in reason for reason in result.blocking_reasons)

    policy_item = next(
        item for item in result.inventory_items
        if item.source_path == "firewall policy"
        and item.source_id == "1"
    )
    assert policy_item.requires_manual_review is True
    assert "unresolved-reference:MISSING-SRC6" in policy_item.notes
    assert "unresolved-reference:MISSING-DST6" in policy_item.notes

    policy_section = next(
        section for section in result.source_sections
        if section.path == "firewall policy"
    )
    assert policy_section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert policy_section.unresolved_dependencies == 2
    assert len(
        [
            entry for entry in result.canonical_ir.audit_entries
            if entry.category == "FortiGate Dependency"
            and entry.message.find("srcaddr6") >= 0
        ]
    ) == 1
    assert len(
        [
            entry for entry in result.canonical_ir.audit_entries
            if entry.category == "FortiGate Dependency"
            and entry.message.find("dstaddr6") >= 0
        ]
    ) == 1


@pytest.mark.parametrize(
    ("source_path", "field", "target_path", "expected_type"),
    [
        ("router policy", "input-device", "system interface", "system interface"),
        ("router policy", "output-device", "system interface", "system interface"),
        ("router policy", "srcaddr", "firewall address", "firewall address"),
        ("router policy", "srcaddr", "firewall addrgrp", "firewall address"),
        ("router policy", "dstaddr", "firewall address", "firewall address"),
        ("router policy", "dstaddr", "firewall addrgrp", "firewall address"),
        (
            "router policy",
            "internet-service-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
        ("router policy6", "input-device", "system interface", "system interface"),
        ("router policy6", "output-device", "system interface", "system interface"),
        ("router policy6", "srcaddr", "firewall address6", "firewall address6"),
        ("router policy6", "srcaddr", "firewall addrgrp6", "firewall address6"),
        ("router policy6", "dstaddr", "firewall address6", "firewall address6"),
        ("router policy6", "dstaddr", "firewall addrgrp6", "firewall address6"),
        (
            "router policy6",
            "internet-service-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
    ],
)
def test_policy_route_dependency_matrix(
    source_path: str,
    field: str,
    target_path: str,
    expected_type: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "target"),
            _item(source_path, "policy", commands=[(field, ["target"])]),
        ]
    )[0]

    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == expected_type
    assert dependency.target_path == target_path


@pytest.mark.parametrize(
    ("source_path", "field", "target_path", "expected_type"),
    [
        ("firewall local-in-policy", "intf", "system interface", "system interface"),
        ("firewall local-in-policy", "srcaddr", "firewall address", "firewall address"),
        ("firewall local-in-policy", "srcaddr", "firewall addrgrp", "firewall address"),
        ("firewall local-in-policy", "dstaddr", "firewall address", "firewall address"),
        ("firewall local-in-policy", "dstaddr", "firewall addrgrp", "firewall address"),
        ("firewall local-in-policy", "service", "firewall service custom", "firewall service custom"),
        ("firewall local-in-policy", "service", "firewall service group", "firewall service custom"),
        (
            "firewall local-in-policy",
            "schedule",
            "firewall schedule recurring",
            "firewall schedule recurring",
        ),
        (
            "firewall local-in-policy",
            "schedule",
            "firewall schedule onetime",
            "firewall schedule recurring",
        ),
        (
            "firewall local-in-policy",
            "schedule",
            "firewall schedule group",
            "firewall schedule recurring",
        ),
        (
            "firewall local-in-policy",
            "internet-service-src-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
        (
            "firewall local-in-policy",
            "internet-service-src-custom-group",
            "firewall internet-service-custom-group",
            "firewall internet-service-custom-group",
        ),
        (
            "firewall local-in-policy",
            "internet-service-src-group",
            "firewall internet-service-group",
            "firewall internet-service-group",
        ),
        ("firewall local-in-policy6", "intf", "system interface", "system interface"),
        ("firewall local-in-policy6", "srcaddr", "firewall address6", "firewall address6"),
        ("firewall local-in-policy6", "srcaddr", "firewall addrgrp6", "firewall address6"),
        ("firewall local-in-policy6", "dstaddr", "firewall address6", "firewall address6"),
        ("firewall local-in-policy6", "dstaddr", "firewall addrgrp6", "firewall address6"),
        ("firewall local-in-policy6", "service", "firewall service custom", "firewall service custom"),
        ("firewall local-in-policy6", "service", "firewall service group", "firewall service custom"),
        (
            "firewall local-in-policy6",
            "schedule",
            "firewall schedule recurring",
            "firewall schedule recurring",
        ),
        (
            "firewall local-in-policy6",
            "schedule",
            "firewall schedule onetime",
            "firewall schedule recurring",
        ),
        (
            "firewall local-in-policy6",
            "schedule",
            "firewall schedule group",
            "firewall schedule recurring",
        ),
        (
            "firewall local-in-policy6",
            "internet-service6-src-custom",
            "firewall internet-service-custom",
            "firewall internet-service-custom",
        ),
        (
            "firewall local-in-policy6",
            "internet-service6-src-custom-group",
            "firewall internet-service-custom-group",
            "firewall internet-service-custom-group",
        ),
        (
            "firewall local-in-policy6",
            "internet-service6-src-group",
            "firewall internet-service-group",
            "firewall internet-service-group",
        ),
    ],
)
def test_local_in_dependency_matrix(
    source_path: str,
    field: str,
    target_path: str,
    expected_type: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "target"),
            _item(source_path, "local-in", commands=[(field, ["target"])]),
        ]
    )[0]

    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == expected_type
    assert dependency.target_path == target_path


@pytest.mark.parametrize(
    ("source_path", "field", "target_path"),
    [
        ("router policy", "srcaddr", "firewall address6"),
        ("router policy", "dstaddr", "firewall addrgrp6"),
        ("router policy", "input-device", "system zone"),
        ("router policy", "output-device", "system sdwan zone"),
        ("router policy", "internet-service-custom", "firewall internet-service-custom-group"),
        ("router policy", "internet-service-custom", "firewall internet-service-name"),
        ("router policy6", "srcaddr", "firewall address"),
        ("router policy6", "dstaddr", "firewall addrgrp"),
        ("firewall local-in-policy", "srcaddr", "firewall address6"),
        ("firewall local-in-policy", "dstaddr", "firewall vip"),
        ("firewall local-in-policy", "intf", "system zone"),
        ("firewall local-in-policy", "service", "firewall address"),
        ("firewall local-in-policy6", "srcaddr", "firewall address"),
        ("firewall local-in-policy6", "dstaddr", "firewall vip6"),
    ],
)
def test_policy_route_and_local_in_wrong_family_references_are_unresolved(
    source_path: str,
    field: str,
    target_path: str,
) -> None:
    dependency = build_dependency_registry(
        [
            _item(target_path, "same-name"),
            _item(source_path, "source", commands=[(field, ["same-name"])]),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


@pytest.mark.parametrize(
    ("source_path", "field", "reference"),
    [
        ("router policy", "input-device", "missing-interface"),
        ("router policy", "output-device", "missing-output"),
        ("router policy", "srcaddr", "missing-src"),
        ("router policy", "dstaddr", "missing-dst"),
        ("router policy", "internet-service-custom", "missing-custom"),
        ("router policy6", "srcaddr", "missing-src6"),
        ("router policy6", "input-device", "missing-interface6"),
        ("firewall local-in-policy", "intf", "missing-interface"),
        ("firewall local-in-policy", "srcaddr", "missing-src"),
        ("firewall local-in-policy", "service", "missing-service"),
        ("firewall local-in-policy", "schedule", "missing-schedule"),
        ("firewall local-in-policy6", "dstaddr", "missing-dst6"),
    ],
)
def test_policy_route_and_local_in_missing_references_are_unresolved(
    source_path: str,
    field: str,
    reference: str,
) -> None:
    dependency = build_dependency_registry(
        [_item(source_path, "source", commands=[(field, [reference])])]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_policy_route_literals_are_ignored_but_database_ids_are_external() -> None:
    dependencies = build_dependency_registry(
        [
            _item(
                "router policy",
                "policy",
                commands=[
                    ("src", ["10.0.0.0/24"]),
                    ("dst", ["2001:db8::/64"]),
                    ("gateway", ["192.0.2.1"]),
                    ("internet-service-id", ["65646"]),
                ],
            )
        ]
    )

    assert len(dependencies) == 1
    assert dependencies[0].result == "EXTERNAL"
    assert dependencies[0].reference == "65646"
    assert dependencies[0].target_path is None


def test_source_only_multi_value_dependencies_preserve_order_and_builtins() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system interface", "port1"),
            _item("system interface", "port2"),
            _item("firewall address", "SRC-A"),
            _item("firewall addrgrp", "SRC-GRP"),
            _item(
                "router policy",
                "policy",
                commands=[
                    ("input-device", ["port2", "port1"]),
                    ("srcaddr", ["SRC-A", "SRC-GRP", "MISSING", "all"]),
                ],
            ),
        ]
    )

    assert [(d.source_field, d.reference, d.result) for d in dependencies] == [
        ("input-device", "port2", "RESOLVED"),
        ("input-device", "port1", "RESOLVED"),
        ("srcaddr", "SRC-A", "RESOLVED"),
        ("srcaddr", "SRC-GRP", "RESOLVED"),
        ("srcaddr", "MISSING", "UNRESOLVED"),
    ]


def test_source_only_dependencies_do_not_cross_vdoms() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system interface", "wan", context="root"),
            _item("firewall address", "SRC", context="root"),
            _item(
                "firewall local-in-policy",
                "local-in",
                context="tenant-a",
                commands=[("intf", ["wan"]), ("srcaddr", ["SRC"])],
            ),
        ]
    )

    assert [(d.reference, d.result, d.target_path) for d in dependencies] == [
        ("wan", "UNRESOLVED", None),
        ("SRC", "UNRESOLVED", None),
    ]


def test_local_in_builtin_values_are_ignored_and_database_names_are_external() -> None:
    dependencies = build_dependency_registry(
        [
            _item(
                "firewall local-in-policy",
                "local-in",
                commands=[
                    ("schedule", ["always"]),
                    ("service", ["ALL"]),
                    ("internet-service-src-name", ["Google-Other"]),
                ],
            )
        ]
    )

    assert len(dependencies) == 1
    assert dependencies[0].result == "EXTERNAL"
    assert dependencies[0].target_path is None
    assert dependencies[0].reference == "Google-Other"


def test_pbr_and_local_in_remain_source_only_through_full_extraction() -> None:
    result = extract_fortigate_config(
        """config system interface
    edit \"wan\"
    next
end
config firewall address
    edit \"SRC\"
    next
end
config router policy
    edit 1
        set input-device \"wan\"
        set srcaddr \"SRC\"
        set src \"10.0.0.0/24\"
        set dst \"0.0.0.0/0\"
        set gateway 192.0.2.1
    next
end
config firewall local-in-policy
    edit 2
        set intf \"wan\"
        set srcaddr \"SRC\"
        set service \"ALL\"
        set schedule \"always\"
    next
end
"""
    )

    assert [d.result for d in result.dependencies] == [
        "RESOLVED",
        "RESOLVED",
        "RESOLVED",
        "RESOLVED",
    ]
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.policies == []
    assert len(result.canonical_ir.policy_routes) == 1
    assert len(result.canonical_ir.local_in_policies) == 1


@pytest.mark.parametrize(
    ("source_path", "field", "reference"),
    [
        ("router policy", "internet-service-id", "65646"),
        ("router policy6", "internet-service-id", "70001"),
        ("firewall local-in-policy", "internet-service-src-name", "ISDB-NAME"),
        ("firewall local-in-policy6", "internet-service6-src-name", "ISDB6-NAME"),
    ],
)
def test_catalog_backed_internet_service_references_are_external(
    source_path: str,
    field: str,
    reference: str,
) -> None:
    dependency = build_dependency_registry(
        [_item(source_path, "source", commands=[(field, [reference])])]
    )[0]

    assert dependency.expected_type in {
        "FortiGuard Internet Service ID",
        "firewall internet-service-name",
    }
    assert dependency.result == "EXTERNAL"
    assert dependency.target_path is None
    assert dependency.notes is not None
    assert "FortiGuard" in dependency.notes
    assert "catalog" in dependency.notes or "Database" in dependency.notes


def test_local_in_internet_service_name_prefers_same_context_local_evidence() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall internet-service-name", "TEST-IS"),
            _item(
                "firewall local-in-policy",
                "rule-1",
                commands=[("internet-service-src-name", ["TEST-IS"])],
            ),
        ]
    )

    assert dependencies[0].result == "RESOLVED"
    assert dependencies[0].target_path == "firewall internet-service-name"


def test_local_in_internet_service_name_wrong_family_and_other_vdom_stay_external() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall internet-service-custom", "SHARED-NAME"),
            _item("firewall internet-service-name", "OTHER-VDOM", context="root"),
            _item(
                "firewall local-in-policy",
                "rule-1",
                context="tenant-a",
                commands=[
                    ("internet-service-src-name", ["SHARED-NAME", "OTHER-VDOM"]),
                ],
            ),
        ]
    )

    assert [(d.reference, d.result, d.target_path) for d in dependencies] == [
        ("SHARED-NAME", "EXTERNAL", None),
        ("OTHER-VDOM", "EXTERNAL", None),
    ]


def test_custom_group_members_remain_strict_local_dependencies() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall internet-service-custom", "CUSTOM-IS"),
            _item(
                "firewall internet-service-custom-group",
                "CUSTOM-GROUP",
                commands=[("member", ["CUSTOM-IS", "MISSING-IS"])],
            ),
        ]
    )

    assert [(d.reference, d.result, d.target_path) for d in dependencies] == [
        ("CUSTOM-IS", "RESOLVED", "firewall internet-service-custom"),
        ("MISSING-IS", "UNRESOLVED", None),
    ]


def test_local_in_internet_service_groups_are_strict_and_family_specific() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall internet-service-custom-group", "SHARED-GROUP"),
            _item("firewall internet-service-group", "SOURCE-GROUP"),
            _item(
                "firewall local-in-policy",
                "rule-1",
                commands=[
                    ("internet-service-src-group", ["SOURCE-GROUP", "MISSING-GROUP", "SHARED-GROUP"]),
                ],
            ),
        ]
    )

    assert [(d.reference, d.result, d.target_path) for d in dependencies] == [
        ("SOURCE-GROUP", "RESOLVED", "firewall internet-service-group"),
        ("MISSING-GROUP", "UNRESOLVED", None),
        ("SHARED-GROUP", "UNRESOLVED", None),
    ]


def test_external_dependencies_do_not_propagate_as_unresolved() -> None:
    result = extract_fortigate_config(
        """config firewall local-in-policy
    edit 1
        set internet-service-src-name "ISDB-NAME"
    next
end
"""
    )

    dependency = next(dependency for dependency in result.dependencies)
    assert dependency.result == "EXTERNAL"
    section = next(section for section in result.source_sections if section.path == "firewall local-in-policy")
    assert section.unresolved_dependencies == 0
    item = next(item for item in result.inventory_items if item.source_path == "firewall local-in-policy")
    assert "unresolved-reference:ISDB-NAME" not in item.notes
    assert not any("Unresolved FortiGate reference 'ISDB-NAME'" in reason for reason in result.blocking_reasons)
    assert any("source-only traffic semantics" in reason for reason in result.blocking_reasons)


def test_full_cli_internet_service_dependencies_preserve_values_and_statuses() -> None:
    result = extract_fortigate_config(
        """config firewall internet-service-custom
    edit "CUSTOM-IS"
    next
end
config firewall internet-service-custom-group
    edit "CUSTOM-GROUP"
        set member "CUSTOM-IS"
    next
end
config firewall internet-service-group
    edit "SOURCE-GROUP"
        set direction source
        set member "ISDB-MEMBER"
    next
end
config firewall internet-service-name
    edit "LOCAL-IS"
        set internet-service-id 12345
    next
end
config firewall local-in-policy
    edit 1
        set internet-service-src-custom "CUSTOM-IS"
        set internet-service-src-custom-group "CUSTOM-GROUP"
        set internet-service-src-group "SOURCE-GROUP"
        set internet-service-src-name "LOCAL-IS" "ISDB-NAME"
    next
end
"""
    )

    local_in = [d for d in result.dependencies if d.source_path == "firewall local-in-policy"]
    assert [(d.source_field, d.reference, d.result) for d in local_in] == [
        ("internet-service-src-custom", "CUSTOM-IS", "RESOLVED"),
        ("internet-service-src-custom-group", "CUSTOM-GROUP", "RESOLVED"),
        ("internet-service-src-group", "SOURCE-GROUP", "RESOLVED"),
        ("internet-service-src-name", "LOCAL-IS", "RESOLVED"),
        ("internet-service-src-name", "ISDB-NAME", "EXTERNAL"),
    ]
    group_item = next(item for item in result.inventory_items if item.source_path == "firewall internet-service-group")
    assert group_item.name == "SOURCE-GROUP"
    assert [(command.key, command.values) for command in group_item.commands] == [
        ("direction", ["source"]),
        ("member", ["ISDB-MEMBER"]),
    ]
    policy_item = next(item for item in result.inventory_items if item.source_path == "firewall local-in-policy")
    assert next(command for command in policy_item.commands if command.key == "internet-service-src-name").values == [
        "LOCAL-IS",
        "ISDB-NAME",
    ]


def test_pbr_internet_service_ids_are_external_but_custom_objects_stay_local() -> None:
    result = extract_fortigate_config(
        """config firewall internet-service-custom
    edit "CUSTOM-IS"
    next
end
config router policy
    edit 1
        set internet-service-custom "CUSTOM-IS"
        set internet-service-id 65646 65647
    next
end
config router policy6
    edit 2
        set internet-service-custom "CUSTOM-IS"
        set internet-service-id 70001
    next
end
"""
    )

    assert [
        (d.source_path, d.source_field, d.reference, d.result, d.target_path)
        for d in result.dependencies
    ] == [
        ("router policy", "internet-service-custom", "CUSTOM-IS", "RESOLVED", "firewall internet-service-custom"),
        ("router policy", "internet-service-id", "65646", "EXTERNAL", None),
        ("router policy", "internet-service-id", "65647", "EXTERNAL", None),
        ("router policy6", "internet-service-custom", "CUSTOM-IS", "RESOLVED", "firewall internet-service-custom"),
        ("router policy6", "internet-service-id", "70001", "EXTERNAL", None),
    ]
    assert result.generation_safe is False
    assert not any("Unresolved FortiGate reference '65646'" in reason for reason in result.blocking_reasons)


def test_internet_service_group_direction_is_preserved_without_semantic_reclassification() -> None:
    result = extract_fortigate_config(
        """config firewall internet-service-group
    edit "DESTINATION-GROUP"
        set direction destination
    next
end
config firewall local-in-policy
    edit 1
        set internet-service-src-group "DESTINATION-GROUP"
    next
end
"""
    )

    dependency = next(dependency for dependency in result.dependencies)
    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall internet-service-group"
    assert not any(dependency.result == "UNRESOLVED" for dependency in result.dependencies)
