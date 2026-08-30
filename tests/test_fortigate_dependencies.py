import pytest

from fwmigrate.extraction.models import (
    DependencyRecord,
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
            _item(
                "firewall policy",
                "policy-1",
                context="tenant-a",
                commands=[
                    ("dstintf", ["shared-zone"]),
                    ("dstaddr", ["shared-vip"]),
                ],
            ),
        ]
    )

    assert [(dependency.reference, dependency.result) for dependency in dependencies] == [
        ("shared-zone", "UNRESOLVED"),
        ("shared-vip", "UNRESOLVED"),
    ]


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
