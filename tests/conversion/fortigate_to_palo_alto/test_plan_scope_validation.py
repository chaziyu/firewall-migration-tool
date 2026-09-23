from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedStaticRoute,
)
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan


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
