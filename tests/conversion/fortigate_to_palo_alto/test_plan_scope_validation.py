from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedStaticRoute,
)
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan


def test_duplicate_device_interfaces_across_vsys_block_both_and_dependents():
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedInterface, PlannedZone
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    interfaces = tuple(PlannedInterface(source_object_type="interface", source_vdom=vdom,
        source_name="port1", target_name="ethernet1/3", target_vsys=vsys,
        status=PANMigrationStatus.SUPPORTED, interface_family="ethernet", virtual_router="default")
        for vdom, vsys in (("root", "vsys1"), ("branch", "vsys2")))
    zones = tuple(PlannedZone(source_object_type="zone", source_vdom=item.source_vdom,
        source_name="trust", target_name="trust", target_vsys=item.target_vsys,
        status=PANMigrationStatus.SUPPORTED, interfaces=(item.target_name,)) for item in interfaces)
    plan = PANMigrationPlan(interfaces=interfaces, zones=zones)
    validation = validate_plan(plan)
    assert len([item for item in validation.issues if item.code == "TARGET_INTERFACE_ALREADY_ASSIGNED"]) == 2
    assert not validation.renderable_item_keys
    assert not PANSetRenderer().render(plan).commands
    child = replace(interfaces[0], source_name="vlan201", target_name="ethernet1/3.201", parent="ethernet1/3", tag=201)
    assert not PANSetRenderer().render(PANMigrationPlan(interfaces=(*interfaces, child))).commands
    distinct = tuple(replace(item, target_name=f"ethernet1/3.{201 + index}", parent="ethernet1/3", tag=201 + index)
                     for index, item in enumerate(interfaces))
    assert not [item for item in validate_plan(PANMigrationPlan(interfaces=distinct)).issues
                if item.code == "TARGET_INTERFACE_ALREADY_ASSIGNED"]


def test_device_scoped_route_does_not_require_target_vsys():
    route = PlannedStaticRoute(
        source_object_type="static_route", source_name="default", target_name="default",
        target_vsys=None, status=PANMigrationStatus.SUPPORTED,
        destination="0.0.0.0/0", nexthop_type="ip-address", nexthop="192.0.2.1",
        virtual_router="default",
    )
    result = validate_plan(PANMigrationPlan(static_routes=(route,)))
    assert not result.issues
    assert result.renderable_item_keys
