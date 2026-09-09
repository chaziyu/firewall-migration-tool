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


def _route_dependency(
    route_path: str,
    target_path: str | None,
    *,
    reference: str = "banking",
    context: str = "root",
) -> DependencyRecord:
    items = []
    if target_path is not None:
        items.append(_item(target_path, reference, context=context))
    items.append(
        _item(
            route_path,
            "1",
            context=context,
            commands=[("dstaddr", [reference])],
        )
    )
    return build_dependency_registry(items)[0]


@pytest.mark.parametrize(
    "target_path",
    ["firewall address", "firewall addrgrp"],
)
def test_router_static_dstaddr_resolves_ipv4_address_targets(
    target_path: str,
) -> None:
    dependency = _route_dependency("router static", target_path)

    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == "firewall address"
    assert dependency.target_path == target_path


def test_router_static_dstaddr_missing_object_is_unresolved() -> None:
    dependency = _route_dependency("router static", None)

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address"
    assert dependency.target_path is None


@pytest.mark.parametrize(
    "target_path",
    ["firewall address6", "firewall addrgrp6"],
)
def test_router_static6_dstaddr_resolves_ipv6_address_targets(
    target_path: str,
) -> None:
    dependency = _route_dependency("router static6", target_path)

    assert dependency.result == "RESOLVED"
    assert dependency.expected_type == "firewall address6"
    assert dependency.target_path == target_path


@pytest.mark.parametrize("target_path", ["firewall address", "firewall addrgrp"])
def test_router_static6_dstaddr_does_not_resolve_ipv4_targets(
    target_path: str,
) -> None:
    dependency = _route_dependency("router static6", target_path)

    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "firewall address6"
    assert dependency.target_path is None


@pytest.mark.parametrize(
    ("route_path", "target_path"),
    [
        ("router static", "firewall address6"),
        ("router static", "firewall vip"),
        ("router static", "firewall vipgrp"),
        ("router static6", "firewall vip6"),
        ("router static6", "firewall vipgrp6"),
        ("router static6", "firewall service custom"),
        ("router static6", "system interface"),
        ("router static6", "system sdwan zone"),
    ],
)
def test_static_route_dstaddr_does_not_resolve_unrelated_object_types(
    route_path: str,
    target_path: str,
) -> None:
    dependency = _route_dependency(route_path, target_path)

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_static_route_dstaddr_resolves_each_preserved_value_independently() -> None:
    dependencies = build_dependency_registry(
        [
            _item("firewall address", "remote-a"),
            _item("firewall addrgrp", "remote-b"),
            _item(
                "router static",
                "1",
                commands=[("dstaddr", ["remote-a", "remote-b"])],
            ),
        ]
    )

    assert [(item.reference, item.result, item.target_path) for item in dependencies] == [
        ("remote-a", "RESOLVED", "firewall address"),
        ("remote-b", "RESOLVED", "firewall addrgrp"),
    ]


def test_route_dstaddr_dependency_preserves_parser_context_and_reference() -> None:
    result = extract_fortigate_config(
        '''
config vdom
    edit "tenant-a"
        config firewall address
            edit "banking"
                set subnet 198.51.100.0 255.255.255.0
            next
        end
        config router static
            edit 1
                set dstaddr "banking"
            next
        end
    next
end
'''
    )

    dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "router static"
    ]

    assert len(dependencies) == 1
    dependency = dependencies[0]
    assert dependency.source_context == "tenant-a"
    assert dependency.source_field == "dstaddr"
    assert dependency.reference == "banking"
    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall address"


def test_parser_preserves_multiple_route_dstaddr_values_independently() -> None:
    result = extract_fortigate_config(
        '''
config firewall address
    edit "remote-a"
        set subnet 198.51.100.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "remote-b"
        set member "remote-a"
    next
end
config router static
    edit 1
        set dstaddr "remote-a" "remote-b"
    next
end
'''
    )

    dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "router static"
    ]

    assert [(item.reference, item.result) for item in dependencies] == [
        ("remote-a", "RESOLVED"),
        ("remote-b", "RESOLVED"),
    ]


def test_route_dstaddr_dependency_does_not_cross_vdom_contexts() -> None:
    route = _item(
        "router static",
        "1",
        context="tenant-a",
        commands=[("dstaddr", ["banking"])],
    )
    root_address = _item("firewall address", "banking", context="root")

    unresolved = build_dependency_registry([root_address, route])[0]
    assert unresolved.result == "UNRESOLVED"

    tenant_address = _item("firewall address", "banking", context="tenant-a")
    resolved = build_dependency_registry([root_address, tenant_address, route])[0]
    assert resolved.result == "RESOLVED"
    assert resolved.source_context == "tenant-a"
    assert resolved.target_path == "firewall address"


def test_missing_route_dstaddr_dependency_blocks_generation_through_extractor() -> None:
    result = extract_fortigate_config(
        '''
config router static
    edit 1
        set dstaddr "banking"
    next
end
'''
    )

    dependency = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "router static"
    )

    assert dependency.result == "UNRESOLVED"
    assert result.generation_safe is False
    assert any(
        "Unresolved FortiGate reference 'banking'" in reason
        for reason in result.blocking_reasons
    )
