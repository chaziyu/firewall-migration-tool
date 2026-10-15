from copy import deepcopy
from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planning.interfaces import plan_interfaces
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig


def source(mode='active'):
    return FGConfig(interfaces=[
        FGInterface(name='port1', type='physical'), FGInterface(name='port2', type='physical'),
        FGInterface(name='bond', type='aggregate', members=['port1', 'port2'],
                    ip='192.0.2.1/24', raw_extra={'lacp-mode': mode} if mode else {}),
        FGInterface(name='vlan10', type='vlan', interface='bond', vlanid=10, ip='198.51.100.1/24'),
    ])


def options(**changes):
    mappings = {'port1': {'target_interface': 'ethernet1/1'}, 'port2': {'target_interface': 'ethernet1/2'},
                'bond': {'target_interface': 'ae1'}, 'vlan10': {'target_interface': 'ae1.10'}}
    mappings.update(changes)
    return PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'vr-root'}}, interfaces={'root': mappings})


@pytest.mark.parametrize('mode', ['static', 'active', 'passive'])
def test_explicit_aggregate_modes_render_before_members_and_vlan_units(mode):
    config = source(mode)
    before = deepcopy(config)
    items = plan_interfaces(config, options())
    assert [item.source_name for item in items] == ['bond', 'vlan10']
    assert all(item.status is PANMigrationStatus.SUPPORTED for item in items)
    # Source order must not put child commands before their aggregate.
    rendered = PANSetRenderer().render(PANMigrationPlan(interfaces=items[::-1]))
    commands = rendered.commands
    assert commands.index('set network interface aggregate-ethernet ae1 layer3') < commands.index(
        'set network interface ethernet ethernet1/1 aggregate-group ae1') < commands.index(
        'set network interface aggregate-ethernet ae1 layer3 units ae1.10')
    assert f'set network interface aggregate-ethernet ae1 layer3 lacp enable {"no" if mode == "static" else "yes"}' in commands
    assert any(f'lacp mode {mode}' in command for command in commands) == (mode != 'static')
    assert not any('ethernet ethernet1/1 layer3' in command for command in commands)
    assert config == before


@pytest.mark.parametrize('change', ['mode', 'absent_mode', 'member_ip', 'unknown', 'duplicate', 'missing', 'zone', 'redundant'])
def test_unsupported_aggregate_semantics_block_parent_and_vlan(change):
    config = source()
    mappings = options()
    if change == 'mode':
        config.interfaces[2].raw_extra['lacp-mode'] = 'unknown'
    elif change == 'absent_mode':
        config.interfaces[2].raw_extra.clear()
    elif change == 'member_ip':
        config.interfaces[0].ip = '203.0.113.1/24'
    elif change == 'unknown':
        config.interfaces[2].raw_extra['min-links'] = 2
    elif change == 'duplicate':
        mappings = options(port2={'target_interface': 'ethernet1/1'})
    elif change == 'missing':
        mappings = options(port2={})
    elif change == 'zone':
        mappings = options(port1={'target_interface': 'ethernet1/1', 'target_zone': 'standalone'})
    else:
        config.interfaces[2].type = 'redundant'
    items = plan_interfaces(config, mappings)
    assert items[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=items)).commands == ()


def test_aggregate_conflicts_with_standalone_or_other_aggregate_allocations():
    parent, child = plan_interfaces(source(), options())
    other = replace(parent, source_name='other', target_name='ae2')
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=(parent, child, other))).commands == ()
    physical = replace(parent, source_name='standalone', interface_family='ethernet', target_name='ethernet1/1',
                       aggregate_members=(), lacp_mode=None)
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=(parent, child, physical))).commands == ()


def test_shared_source_members_block_both_aggregate_owners():
    config = source()
    config.interfaces.append(FGInterface(name='other', type='aggregate', members=['port1'], raw_extra={'lacp-mode': 'static'}))
    items = plan_interfaces(config, options(other={'target_interface': 'ae2'}))
    assert all(item.status is PANMigrationStatus.MANUAL_REVIEW for item in items if not item.parent)
