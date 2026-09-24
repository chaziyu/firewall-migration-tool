from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedStaticRoute,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer


def test_virtual_router_gateway_and_blackhole_route_commands():
    plan = PANMigrationPlan(static_routes=(
        PlannedStaticRoute(source_object_type="static_route", source_name="default", target_vsys="vsys1",
                           status=PANMigrationStatus.SUPPORTED, virtual_router="default",
                           destination="0.0.0.0/0", interface="ethernet1/2", nexthop_type="ip-address",
                           nexthop="192.0.2.1", admin_distance=10),
        PlannedStaticRoute(source_object_type="static_route", source_name="blackhole", target_vsys="vsys1",
                           status=PANMigrationStatus.SUPPORTED, virtual_router="default",
                           destination="198.51.100.0/24", nexthop_type="discard"),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0",
        "set network virtual-router default routing-table ip static-route default interface ethernet1/2",
        "set network virtual-router default routing-table ip static-route default nexthop ip-address 192.0.2.1",
        "set network virtual-router default routing-table ip static-route default admin-dist 10",
        "set network virtual-router default routing-table ip static-route blackhole destination 198.51.100.0/24",
        "set network virtual-router default routing-table ip static-route blackhole nexthop discard",
    )
