import ast
from pathlib import Path

from fwmigrate.conversion import MigrationPlannerRegistry
from fwmigrate.conversion.fortigate_to_palo_alto import (
    FortiGateToPaloAltoPlanner,
    PANMigrationPlan,
)


class _Planner:
    source_vendor = "cisco_asa"
    target_vendor = "fortigate"


def test_future_planner_registry_is_directional_and_empty_by_default():
    registry = MigrationPlannerRegistry()
    planner = _Planner()

    registry.register(planner)

    assert registry.get("CISCO_ASA", "FortiGate") is planner


def test_unimplemented_migration_pair_fails_closed():
    try:
        MigrationPlannerRegistry().get("cisco_asa", "fortigate")
    except KeyError as exc:
        assert "cisco_asa_to_fortigate" in str(exc)
    else:
        raise AssertionError("unimplemented migration pair must not be available")


def test_fortigate_to_palo_alto_planner_returns_a_plan():
    plan = FortiGateToPaloAltoPlanner().plan(object(), object())

    assert isinstance(plan, PANMigrationPlan)
    assert not hasattr(plan, "config")


def test_planning_boundary_does_not_depend_on_target_config_or_shared_ir():
    root = Path(__file__).parents[2] / "src" / "fwmigrate" / "conversion"
    forbidden = {"PANOSConfig", "IRConfig", "TargetVendorConfig", "FGConfig"}

    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        assert not forbidden & (names | attributes), path
