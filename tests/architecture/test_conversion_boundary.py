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


def test_planner_registry_is_directional_and_empty_by_default():
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


def test_pair_package_uses_grouped_modules_without_top_level_compatibility_shims():
    conversion_root = Path(__file__).parents[2] / "src" / "fwmigrate" / "conversion"
    pair_roots = tuple(conversion_root / name for name in (
        "fortigate_to_palo_alto", "palo_alto_to_fortigate", "fortigate_to_juniper_srx",
        "fortigate_to_cisco_asa", "fortigate_to_checkpoint",
        "palo_alto_to_juniper_srx", "palo_alto_to_cisco_asa", "palo_alto_to_checkpoint",
        "palo_alto_to_cisco_ftd",
    ))
    retired_shims = {
        "addresses.py", "admin_suggestions.py", "cli_paths.py", "dhcp.py",
        "external_resource_suggestions.py", "identity_suggestions.py", "interfaces.py",
        "nat.py", "policies.py", "recommendation_engine.py", "renderer.py",
        "review_context.py", "review_evidence.py", "review_workflow.py", "routing.py",
        "schedules.py", "sdwan_suggestions.py", "security_suggestions.py", "services.py",
        "ssl_vpn_suggestions.py", "support_guidance.py", "target_candidates.py",
        "target_evidence.py", "target_intent.py", "target_object_reuse.py",
        "target_plan_validation.py", "target_suggestions.py", "target_validation.py",
        "topology.py", "vpn_suggestions.py",
    }

    for package in pair_roots:
        assert not {path.name for path in package.iterdir() if path.is_file()} & retired_shims
