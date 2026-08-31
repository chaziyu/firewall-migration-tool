from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _route_dependencies(content: str):
    result = extract_fortigate_config(content)
    return [
        dependency
        for dependency in result.dependencies
        if dependency.source_path in {"router static", "router static6"}
    ]


def _sdwan_config(*zones: str) -> str:
    zone_edits = "\n".join(
        f'        edit "{zone}"\n        next'
        for zone in zones
    )
    return f'''config system sdwan
    config zone
{zone_edits}
    end
end
'''


def _route_config(section: str, values: str, route_id: int = 1) -> str:
    destination = "2001:db8::/64" if section.endswith("6") else "192.0.2.0 255.255.255.0"
    return f'''config {section}
    edit {route_id}
        set dst {destination}
        set sdwan-zone {values}
    next
end
'''


def test_router_static_sdwan_zone_dependency_resolves() -> None:
    dependencies = _route_dependencies(
        _sdwan_config("zone-a")
        + _route_config("router static", '"zone-a"')
    )

    assert [(item.source_field, item.reference, item.result, item.target_path) for item in dependencies] == [
        ("sdwan-zone", "zone-a", "RESOLVED", "system sdwan zone"),
    ]
    assert dependencies[0].expected_type == "system sdwan zone"


def test_missing_router_static_sdwan_zone_remains_unresolved() -> None:
    result = extract_fortigate_config(
        _route_config("router static", '"missing-zone"')
    )
    dependencies = [
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "router static"
    ]

    assert [(item.reference, item.result, item.target_path) for item in dependencies] == [
        ("missing-zone", "UNRESOLVED", None),
    ]
    assert result.generation_safe is False
    assert "missing-zone" in result.blocking_reasons[0]
    route_section = next(
        section for section in result.source_sections
        if section.path == "router static"
    )
    assert route_section.unresolved_dependencies == 1


def test_router_static6_sdwan_zone_dependency_resolves() -> None:
    dependencies = _route_dependencies(
        _sdwan_config("zone-v6")
        + _route_config("router static6", '"zone-v6"', route_id=6)
    )

    assert [(item.source_path, item.reference, item.result, item.target_path) for item in dependencies] == [
        ("router static6", "zone-v6", "RESOLVED", "system sdwan zone"),
    ]


def test_multiple_static_route_sdwan_zones_are_checked_in_source_order() -> None:
    dependencies = _route_dependencies(
        _sdwan_config("zone-a", "zone-c")
        + _route_config("router static", '"zone-a" "missing-zone" "zone-c"')
    )

    assert [
        (item.reference, item.result, item.target_path)
        for item in dependencies
    ] == [
        ("zone-a", "RESOLVED", "system sdwan zone"),
        ("missing-zone", "UNRESOLVED", None),
        ("zone-c", "RESOLVED", "system sdwan zone"),
    ]


def test_route_sdwan_zone_does_not_resolve_generic_interface_or_system_zone() -> None:
    content = '''config system interface
    edit "zone-a"
    next
end
config system zone
    edit "zone-b"
    next
end
'''
    dependencies = _route_dependencies(
        content + _route_config("router static", '"zone-a" "zone-b"')
    )

    assert [(item.reference, item.result, item.target_path) for item in dependencies] == [
        ("zone-a", "UNRESOLVED", None),
        ("zone-b", "UNRESOLVED", None),
    ]


def test_route_device_and_sdwan_zone_keep_separate_dependency_types() -> None:
    content = '''config system interface
    edit "wan1"
    next
end
'''
    content += _sdwan_config("zone-a")
    content += '''config router static
    edit 1
        set dst 192.0.2.0 255.255.255.0
        set device "wan1"
        set sdwan-zone "zone-a"
    next
end
'''

    dependencies = _route_dependencies(content)

    assert [
        (item.source_field, item.reference, item.expected_type, item.result, item.target_path)
        for item in dependencies
    ] == [
        ("device", "wan1", "system interface", "RESOLVED", "system interface"),
        ("sdwan-zone", "zone-a", "system sdwan zone", "RESOLVED", "system sdwan zone"),
    ]


def test_route_sdwan_zone_does_not_cross_vdoms() -> None:
    content = _sdwan_config("virtual-wan-link") + '''config vdom
    edit "tenant-a"
        config router static
            edit 4
                set dst 192.0.2.0 255.255.255.0
                set sdwan-zone "virtual-wan-link"
            next
        end
    next
end
'''

    dependencies = _route_dependencies(content)

    assert len(dependencies) == 1
    assert dependencies[0].source_context == "tenant-a"
    assert dependencies[0].reference == "virtual-wan-link"
    assert dependencies[0].result == "UNRESOLVED"
    assert dependencies[0].target_path is None


def test_route_sdwan_zone_resolves_when_zone_exists_in_same_vdom() -> None:
    content = _sdwan_config("virtual-wan-link") + '''config vdom
    edit "tenant-a"
        config system sdwan
            config zone
                edit "virtual-wan-link"
                next
            end
        end
        config router static
            edit 4
                set dst 192.0.2.0 255.255.255.0
                set sdwan-zone "virtual-wan-link"
            next
        end
    next
end
'''

    dependencies = _route_dependencies(content)

    assert len(dependencies) == 1
    assert dependencies[0].source_context == "tenant-a"
    assert dependencies[0].reference == "virtual-wan-link"
    assert dependencies[0].result == "RESOLVED"
    assert dependencies[0].target_path == "system sdwan zone"
