import pytest

from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry


def _item(
    source_path: str,
    name: str,
    *,
    context: str = "root",
    source_id: str | None = None,
    commands: list[tuple[str, list[str]]] | None = None,
) -> SourceInventoryItem:
    return SourceInventoryItem(
        domain=source_path.split(" ", 1)[0],
        source_path=source_path,
        name=name,
        source_id=source_id,
        source_context=context,
        commands=[
            SourceCommand(operation="set", key=field, values=values)
            for field, values in (commands or [])
        ],
    )


def _dependency(
    dependencies,
    source_path: str,
    field: str,
    reference: str,
):
    return next(
        dependency
        for dependency in dependencies
        if dependency.source_path == source_path
        and dependency.source_field == field
        and dependency.reference == reference
    )


@pytest.mark.parametrize(
    ("source_path", "field", "target_path", "reference", "expected_type"),
    [
        (
            "system sdwan members",
            "interface",
            "system interface",
            "wan1",
            "system interface",
        ),
        (
            "system sdwan members",
            "zone",
            "system sdwan zone",
            "WAN",
            "system sdwan zone",
        ),
        (
            "system sdwan health-check",
            "members",
            "system sdwan members",
            "1",
            "system sdwan members",
        ),
        (
            "system sdwan service",
            "health-check",
            "system sdwan health-check",
            "internet",
            "system sdwan health-check",
        ),
        (
            "system sdwan service",
            "priority-members",
            "system sdwan members",
            "1",
            "system sdwan members",
        ),
        (
            "system sdwan service",
            "priority-zone",
            "system sdwan zone",
            "WAN",
            "system sdwan zone",
        ),
        (
            "system sdwan service",
            "src",
            "firewall address",
            "LAN",
            "firewall address",
        ),
        (
            "system sdwan service",
            "dst",
            "firewall addrgrp",
            "SERVERS",
            "firewall address",
        ),
    ],
)
def test_sdwan_dependency_rules_resolve_their_explicit_target_types(
    source_path: str,
    field: str,
    target_path: str,
    reference: str,
    expected_type: str,
) -> None:
    target_source_id = reference if target_path == "system sdwan members" else None
    dependencies = build_dependency_registry(
        [
            _item(
                target_path,
                reference,
                source_id=target_source_id,
            ),
            _item(
                source_path,
                "source-object",
                commands=[(field, [reference])],
            ),
        ]
    )

    dependency = _dependency(dependencies, source_path, field, reference)
    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == expected_type
    assert dependency.target_path == target_path


def test_sdwan_member_interface_missing_reference_is_unresolved() -> None:
    dependency = build_dependency_registry(
        [
            _item(
                "system sdwan members",
                "1",
                source_id="1",
                commands=[("interface", ["missing-wan"])],
            )
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "system interface"
    assert dependency.target_path is None


def test_sdwan_member_zone_missing_reference_is_unresolved() -> None:
    dependency = build_dependency_registry(
        [
            _item(
                "system sdwan members",
                "1",
                source_id="1",
                commands=[("zone", ["missing-zone"])],
            )
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "system sdwan zone"


def test_virtual_wan_link_is_not_an_implicit_sdwan_zone() -> None:
    dependency = build_dependency_registry(
        [
            _item(
                "system sdwan members",
                "1",
                source_id="1",
                commands=[("zone", ["virtual-wan-link"])],
            )
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"


def test_sdwan_health_check_member_ids_resolve_independently() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system sdwan members", "member-one", source_id="1"),
            _item("system sdwan members", "member-two", source_id="2"),
            _item(
                "system sdwan health-check",
                "internet",
                commands=[("members", ["1", "2", "3"])],
            ),
        ]
    )

    member_dependencies = [
        dependency
        for dependency in dependencies
        if dependency.source_path == "system sdwan health-check"
    ]
    assert [
        (dependency.reference, dependency.result)
        for dependency in member_dependencies
    ] == [
        ("1", "RESOLVED"),
        ("2", "RESOLVED"),
        ("3", "UNRESOLVED"),
    ]


def test_sdwan_priority_member_ids_preserve_order_and_do_not_match_interfaces() -> None:
    dependencies = build_dependency_registry(
        [
            _item("system interface", "10"),
            _item("system sdwan members", "member-ten", source_id="10"),
            _item("system sdwan members", "member-twenty", source_id="20"),
            _item(
                "system sdwan service",
                "service-1",
                commands=[("priority-members", ["20", "10"])],
            ),
        ]
    )

    priority_dependencies = [
        dependency
        for dependency in dependencies
        if dependency.source_path == "system sdwan service"
    ]
    assert [dependency.reference for dependency in priority_dependencies] == [
        "20",
        "10",
    ]
    assert all(
        dependency.result == "RESOLVED"
        and dependency.target_path == "system sdwan members"
        for dependency in priority_dependencies
    )


@pytest.mark.parametrize("field", ["health-check", "priority-zone"])
def test_sdwan_service_missing_named_references_are_unresolved(field: str) -> None:
    expected_type = (
        "system sdwan health-check"
        if field == "health-check"
        else "system sdwan zone"
    )
    dependency = build_dependency_registry(
        [
            _item(
                "system sdwan service",
                "service-1",
                commands=[(field, ["missing-reference"])],
            )
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == expected_type


@pytest.mark.parametrize("field", ["src", "dst"])
def test_sdwan_service_addresses_do_not_resolve_vips(field: str) -> None:
    dependency = build_dependency_registry(
        [
            _item("firewall vip", "published-vip"),
            _item(
                "system sdwan service",
                "service-1",
                commands=[(field, ["published-vip"])],
            ),
        ]
    )[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address"


def test_sdwan_dependencies_are_context_scoped_for_duplicate_names_and_ids() -> None:
    source_cases = [
        (
            "system sdwan members",
            "interface",
            "wan1",
            "system interface",
        ),
        (
            "system sdwan members",
            "zone",
            "WAN",
            "system sdwan zone",
        ),
        (
            "system sdwan health-check",
            "members",
            "1",
            "system sdwan members",
        ),
        (
            "system sdwan service",
            "health-check",
            "internet",
            "system sdwan health-check",
        ),
        (
            "system sdwan service",
            "priority-members",
            "1",
            "system sdwan members",
        ),
        (
            "system sdwan service",
            "priority-zone",
            "WAN",
            "system sdwan zone",
        ),
        (
            "system sdwan service",
            "src",
            "LAN",
            "firewall address",
        ),
        (
            "system sdwan service",
            "dst",
            "SERVERS",
            "firewall addrgrp",
        ),
    ]

    items = []
    for source_path, field, reference, target_path in source_cases:
        source_id = reference if target_path == "system sdwan members" else None
        items.extend(
            [
                _item(
                    target_path,
                    reference,
                    context="root",
                    source_id=source_id,
                ),
                _item(
                    target_path,
                    reference,
                    context="tenant-a",
                    source_id=source_id,
                ),
                _item(
                    source_path,
                    f"source-{reference}",
                    context="tenant-a",
                    commands=[(field, [reference])],
                ),
                _item(
                    source_path,
                    f"cross-vdom-{reference}",
                    context="tenant-b",
                    commands=[(field, [reference])],
                ),
            ]
        )

    dependencies = build_dependency_registry(items)
    for source_path, field, reference, target_path in source_cases:
        tenant_dependency = _dependency(
            [
                dependency
                for dependency in dependencies
                if dependency.source_context == "tenant-a"
            ],
            source_path,
            field,
            reference,
        )
        cross_vdom_dependency = _dependency(
            [
                dependency
                for dependency in dependencies
                if dependency.source_context == "tenant-b"
            ],
            source_path,
            field,
            reference,
        )
        assert tenant_dependency.result == "RESOLVED"
        assert tenant_dependency.target_path == target_path
        assert cross_vdom_dependency.result == "UNRESOLVED"
        assert cross_vdom_dependency.target_path is None
