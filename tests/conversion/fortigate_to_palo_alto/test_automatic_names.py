from copy import deepcopy
from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup, PlannedSecurityRule,
)
from fwmigrate.conversion.fortigate_to_palo_alto.planning.naming import allocate_plan_names


def test_route_allocator_reserves_nested_names_on_selected_device():
    from types import SimpleNamespace
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedStaticRoute
    routes = tuple(PlannedStaticRoute(source_vdom=vdom, source_name='1', target_name='1',
        source_object_type='static_route', virtual_router='vr', target_vsys='vsys1') for vdom in ('a', 'b'))
    source = PANMigrationPlan(static_routes=routes)
    first = allocate_plan_names(source)
    reserved = first.static_routes[1].target_name
    router = SimpleNamespace(name='vr', static_routes=[SimpleNamespace(name=reserved)],
        scope=SimpleNamespace(device_serial=None, device_name='fw', template_provenance={}))
    target = SimpleNamespace(config=SimpleNamespace(virtual_routers=[router]))
    allocated = allocate_plan_names(source, target, 'fw')
    assert allocated.static_routes[0].target_name == '1'
    assert allocated.static_routes[1].target_name != reserved
    router.scope.device_name = 'other'
    assert allocate_plan_names(source, target, 'fw') == first


def test_automatic_names_preserve_valid_names_and_rewrite_scoped_references():
    source = PANMigrationPlan(addresses=tuple(PlannedAddress(source_vdom=vdom, source_name='bad/name', target_name='bad/name',
        target_vsys='vsys1', source_kind='address', source_object_type='address', status=PANMigrationStatus.SUPPORTED,
        address_type='ip-netmask', value='192.0.2.1/32') for vdom in ('a', 'b')),
        address_groups=(PlannedAddressGroup(source_vdom='a', source_name='valid', target_name='valid', target_vsys='vsys1',
            source_object_type='address_group', members=('bad/name',)),),
        security_rules=(PlannedSecurityRule(source_vdom='b', source_name='rule', target_name='rule', target_vsys='vsys1',
            source_object_type='security_rule', sources=('bad/name',)),))
    original = deepcopy(source)
    plan = allocate_plan_names(source)
    assert plan == allocate_plan_names(source)
    assert len({item.target_name for item in plan.addresses}) == 2
    assert all('/' not in item.target_name and len(item.target_name) <= 63 for item in plan.addresses)
    assert plan.address_groups[0].target_name == 'valid'
    assert plan.address_groups[0].members == (plan.addresses[0].target_name,)
    assert plan.security_rules[0].sources == (plan.addresses[1].target_name,)
    assert source == original


def test_ambiguous_source_names_do_not_silently_select_a_reference():
    source = PANMigrationPlan(addresses=(PlannedAddress(source_vdom='root', source_name='same', target_name='same', target_vsys='vsys1'),),
        address_groups=(PlannedAddressGroup(source_vdom='root', source_name='same', target_name='same', target_vsys='vsys1', members=('same',)),))
    plan = allocate_plan_names(source)
    assert plan.address_groups[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert any('Ambiguous source' in warning for warning in plan.address_groups[0].warnings)
