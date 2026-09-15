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


def _policy(
    field: str,
    reference: str,
    *,
    context: str = "root",
    name: str = "policy-1",
) -> SourceInventoryItem:
    return _item(
        "firewall policy",
        name,
        context=context,
        commands=[(field, [reference])],
    )


def test_local_object_named_default_resolves_before_builtin_classification() -> None:
    dependency = build_dependency_registry([
        _item("firewall address", "default"),
        _policy("srcaddr", "default"),
    ])[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall address"


def test_default_is_not_globally_suppressed_across_vdoms() -> None:
    dependency = build_dependency_registry([
        _item("firewall address", "default", context="VDOM-A"),
        _policy("srcaddr", "default", context="VDOM-B"),
    ])[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_address_and_schedule_builtins_remain_non_dependencies_without_local_objects() -> None:
    dependencies = build_dependency_registry([
        _policy("srcaddr", "all", name="policy-address"),
        _policy("schedule", "always", name="policy-schedule"),
        _policy("srcintf", "any", name="policy-interface"),
    ])

    assert dependencies == []


def test_local_objects_override_rule_specific_builtin_names() -> None:
    dependencies = build_dependency_registry([
        _item("firewall address", "all"),
        _item("firewall schedule recurring", "always"),
        _item("system interface", "any"),
        _policy("srcaddr", "all", name="policy-address"),
        _policy("schedule", "always", name="policy-schedule"),
        _policy("srcintf", "any", name="policy-interface"),
    ])

    by_object = {dependency.source_object: dependency for dependency in dependencies}
    assert by_object["policy-address"].target_path == "firewall address"
    assert by_object["policy-address"].result == "RESOLVED"
    assert by_object["policy-schedule"].target_path == "firewall schedule recurring"
    assert by_object["policy-schedule"].result == "RESOLVED"
    assert by_object["policy-interface"].target_path == "system interface"
    assert by_object["policy-interface"].result == "RESOLVED"


def test_predefined_service_resolution_is_preserved() -> None:
    dependency = build_dependency_registry([
        _policy("service", "HTTP"),
    ])[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "fortigate predefined service"


def test_all_service_builtin_remains_non_dependency_without_local_object() -> None:
    assert build_dependency_registry([
        _policy("service", "ALL"),
    ]) == []


def test_local_service_named_all_overrides_builtin_name() -> None:
    dependency = build_dependency_registry([
        _item("firewall service custom", "ALL"),
        _policy("service", "ALL"),
    ])[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall service custom"


def test_distinct_duplicate_same_type_targets_fail_closed_as_unresolved() -> None:
    dependency = build_dependency_registry([
        _item(
            "firewall address",
            "DUPLICATE",
            commands=[("subnet", ["192.0.2.1", "255.255.255.255"])],
        ),
        _item(
            "firewall address",
            "DUPLICATE",
            commands=[("subnet", ["198.51.100.1", "255.255.255.255"])],
        ),
        _policy("srcaddr", "DUPLICATE"),
    ])[0]

    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None
    assert dependency.notes is not None
    assert "ambiguous" in dependency.notes.lower()
    assert "2 valid targets" in dependency.notes


def test_equivalent_duplicate_inventory_records_are_one_logical_target() -> None:
    duplicate = _item("firewall address", "SAME")
    dependency = build_dependency_registry([
        duplicate,
        duplicate.model_copy(deep=True),
        _policy("srcaddr", "SAME"),
    ])[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall address"


def test_different_allowed_source_types_preserve_existing_resolution_precedence() -> None:
    dependency = build_dependency_registry([
        _item("firewall address", "COLLISION"),
        _item("firewall addrgrp", "COLLISION"),
        _policy("srcaddr", "COLLISION"),
    ])[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall address"


def test_cross_type_name_collision_uses_only_allowed_target_sections() -> None:
    dependency = build_dependency_registry([
        _item("firewall address", "SHARED"),
        _item("firewall service custom", "SHARED"),
        _policy("srcaddr", "SHARED"),
    ])[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall address"


def test_same_name_in_different_vdoms_is_not_ambiguous() -> None:
    dependencies = build_dependency_registry([
        _item("firewall address", "SHARED", context="VDOM-A"),
        _item("firewall address", "SHARED", context="VDOM-B"),
        _policy("srcaddr", "SHARED", context="VDOM-A", name="policy-a"),
        _policy("srcaddr", "SHARED", context="VDOM-B", name="policy-b"),
    ])

    assert len(dependencies) == 2
    assert all(dependency.result == "RESOLVED" for dependency in dependencies)
    assert all(
        dependency.target_path == "firewall address"
        for dependency in dependencies
    )


def test_identical_name_and_source_id_do_not_create_false_ambiguity() -> None:
    dependency = build_dependency_registry([
        _item("firewall address", "123", source_id="123"),
        _policy("srcaddr", "123"),
    ])[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall address"
