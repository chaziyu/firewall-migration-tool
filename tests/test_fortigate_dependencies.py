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
