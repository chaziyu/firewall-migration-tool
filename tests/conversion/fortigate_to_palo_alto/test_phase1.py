from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.conversion.fortigate_to_palo_alto import (
    FortiGateToPaloAltoPlanner,
    InterfaceMapping,
    PANMigrationOptions,
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedPANItem,
    VDOMMapping,
)
from fwmigrate.conversion.registry import MigrationPlannerRegistry


def test_phase1_package_exports_pair_boundary_types():
    item = PlannedPANItem(
        source_vdom="root",
        source_object_type="address",
        source_name="web",
        status=PANMigrationStatus.SUPPORTED,
    )
    plan = PANMigrationPlan(addresses=(item,))

    assert plan.addresses == (item,)
    assert PANMigrationOptions() == PANMigrationOptions()


def test_builtin_registration_exposes_the_directional_pair():
    registry = MigrationPlannerRegistry()
    planner = FortiGateToPaloAltoPlanner()
    registry.register(planner)

    assert registry.get("FORTIGATE", "PALO_ALTO") is planner


def test_planner_returns_pair_specific_empty_plan_until_mappings_exist():
    plan = FortiGateToPaloAltoPlanner().plan(object(), object())

    assert isinstance(plan, PANMigrationPlan)
    assert plan == PANMigrationPlan()


def test_builtin_registration_function_registers_the_pair_once():
    register_builtin_migration_planners()

    from fwmigrate.conversion.registry import migration_planners

    assert isinstance(
        migration_planners.get("fortigate", "palo_alto"),
        FortiGateToPaloAltoPlanner,
    )


def test_options_coerce_mapping_documents_to_explicit_mapping_models():
    options = PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}},
        interfaces={"root": {"port1": {"target_interface": "ethernet1/1", "target_zone": "trust"}}},
    )

    assert options.vdoms["root"] == VDOMMapping("vsys1", "default")
    assert options.interfaces["root"]["port1"] == InterfaceMapping("ethernet1/1", "trust")
