from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedStaticRoute,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from dataclasses import replace
from fwmigrate.conversion.fortigate_to_palo_alto.planning.naming import allocate_plan_names
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan


def test_source_to_pipeline_preserves_both_vdom_routes_in_one_virtual_router():
    from fwmigrate.conversion.fortigate_to_palo_alto import run_migration_pipeline, PANMigrationOptions
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
    text = 'config vdom\n' + ''.join(f''' edit {vdom}
  config router static
   edit 1
    set dst {subnet} 255.255.255.0
    set blackhole enable
   next
  end
 next
''' for vdom, subnet in (('a', '192.0.2.0'), ('b', '198.51.100.0'))) + 'end\n'
    analysis = FortiGateSourceReporter().analyze_source(text)
    source = analysis.extracted.config
    original = source.model_dump()
    options = PANMigrationOptions(vdoms={'a': {'vsys': 'vsys1', 'virtual_router': 'vr'},
        'b': {'vsys': 'vsys2', 'virtual_router': 'vr'}})
    result = run_migration_pipeline(source, analysis.derived, options=options)
    assert len(result.plan.static_routes) == 2
    assert len({route.target_name for route in result.plan.static_routes}) == 2
    assert any('destination 192.0.2.0/24' in command for command in result.rendered.commands)
    assert any('destination 198.51.100.0/24' in command for command in result.rendered.commands)
    assert source.model_dump() == original


def test_routes_share_virtual_router_namespace_across_vdoms_and_vsys():
    routes = tuple(PlannedStaticRoute(source_vdom=vdom, source_name='1', source_object_type='static_route',
        target_name='1', target_vsys=vsys, status=PANMigrationStatus.SUPPORTED, virtual_router='vr',
        destination=destination, nexthop_type='discard') for vdom, vsys, destination in (
            ('a', 'vsys1', '192.0.2.0/24'), ('b', 'vsys2', '198.51.100.0/24')))
    source = PANMigrationPlan(static_routes=routes)
    assert any(issue.code == 'duplicate_target_name' for issue in validate_plan(source).issues)
    assert not PANSetRenderer().render(source).commands
    plan = allocate_plan_names(source)
    assert plan == allocate_plan_names(source)
    assert plan.static_routes[0].target_name == '1'
    assert len({route.target_name for route in plan.static_routes}) == 2
    artifact = PANSetRenderer().render(plan)
    rows = artifact.report['items']
    for row, route in zip(rows, plan.static_routes):
        assert any(f'destination {route.destination}' in command for command in row['commands'])
        assert all(f' static-route {route.target_name} ' in command for command in row['commands'])
    separate = replace(source, static_routes=(routes[0], replace(routes[1], virtual_router='other', target_vsys='vsys1')))
    assert not validate_plan(separate).has_errors
    assert len(PANSetRenderer().render(separate).commands) == 4
    assert source.static_routes == routes


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


def test_route_priority_or_disabled_state_blocks_cli_generation():
    for item in (
        PlannedStaticRoute(source_name="disabled", status=PANMigrationStatus.SUPPORTED,
            virtual_router="default", destination="192.0.2.0/24", disabled=True),
        PlannedStaticRoute(source_name="priority-zero", status=PANMigrationStatus.SUPPORTED,
            virtual_router="default", destination="192.0.2.0/24", priority=0),
    ):
        assert not __import__("fwmigrate.conversion.fortigate_to_palo_alto.rendering.cli_paths", fromlist=["static_route"]).static_route(item)
