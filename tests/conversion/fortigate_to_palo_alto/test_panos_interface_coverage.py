from copy import deepcopy

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planning.interfaces import plan_interfaces
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig


def test_unplanned_interfaces_preserve_scope_and_source_order_without_duplicates_or_mutation():
    source = FGConfig(interfaces=[FGInterface(name='Port1', vdom='root'), FGInterface(name='port1', vdom='root'),
                                  FGInterface(name='port1', vdom='blue'), FGInterface(name='port1', vdom='root')])
    before = deepcopy(source)
    coverage = build_migration_coverage(source, plan=PANMigrationPlan())
    rows = coverage['unplanned']
    assert [(row['source_vdom'], row['source_name']) for row in rows] == [
        ('blue', 'port1'), ('root', 'Port1'), ('root', 'port1')]
    assert all(row['readiness'] == 'PENDING' for row in rows)
    assert all(row['family'] == 'interface' for row in rows)
    assert coverage['counts']['SOURCE_ONLY'] == coverage['unplanned_count'] == 3
    assert not coverage['complete']
    assert source == before


@pytest.mark.parametrize('missing_member', [False, True])
def test_aggregate_member_coverage_requires_representation_in_parent_plan(missing_member):
    source = FGConfig(interfaces=[FGInterface(name='port1', type='physical'), FGInterface(name='port2', type='physical'),
        FGInterface(name='bond', type='aggregate', members=['port1', 'port2'], raw_extra={'lacp-mode': 'active'})])
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'vr-root'}}, interfaces={'root': {
        'port1': {'target_interface': 'ethernet1/1'}, 'port2': {} if missing_member else {'target_interface': 'ethernet1/2'},
        'bond': {'target_interface': 'ae1'}}})
    plan = PANMigrationPlan(interfaces=plan_interfaces(source, options))
    assert [item.source_name for item in plan.interfaces] == ['bond']
    coverage = build_migration_coverage(source, plan=plan, options=options)
    assert [row['source_name'] for row in coverage['unplanned']] == (['port2'] if missing_member else [])
    assert coverage['complete'] is (not missing_member)


@pytest.mark.parametrize('excluded', [False, True])
def test_unrepresented_mapped_or_excluded_interface_has_explicit_coverage_reason(excluded):
    source = FGConfig(interfaces=[FGInterface(name='port1')])
    options = PANMigrationOptions(interfaces={'root': {'port1': {'target_interface': 'ethernet1/1'}}},
        conversion_settings={'excluded_interfaces': ['root/port1']} if excluded else {})
    coverage = build_migration_coverage(source, plan=PANMigrationPlan(), options=options)
    row, = coverage['unplanned']
    assert row['readiness'] == 'UNSUPPORTED'
    assert ('explicitly excluded' if excluded else 'not represented') in row['reason']
    if excluded:
        planned = PANMigrationPlan(interfaces=plan_interfaces(source, options))
        assert not build_migration_coverage(source, plan=planned, options=options)['unplanned']
