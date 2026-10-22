from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedSchedule,
    PlannedService, PlannedStaticRoute,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan


@pytest.mark.parametrize('family,item', [
    ('addresses', PlannedAddress(source_object_type='address', address_type='ip-netmask', value='192.0.2.1/32')),
    ('services', PlannedService(source_object_type='service', protocol='tcp', destination_port='443')),
    ('schedules', PlannedSchedule(source_object_type='schedule', schedule_type='recurring',
                                  weekly=(('monday', '09:00', '17:00'),))),
])
def test_vsys_scoped_objects_require_placement_before_counting_as_exported(family, item):
    item = replace(item, source_vdom='branch', source_kind=item.source_object_type,
                   source_name='example', target_name='example', status=PANMigrationStatus.SUPPORTED)
    plan = PANMigrationPlan(**{family: (item,)})
    validation = validate_plan(plan)
    assert any(issue.code == 'missing_target_vsys' for issue in validation.issues)
    assert not validation.renderable_item_keys
    rendered = PANSetRenderer().render(plan)
    assert not rendered.commands
    assert rendered.report['summary']['command_renderable'] == rendered.report['summary']['satisfied'] == 0
    row, = rendered.report['items']
    assert row['render_disposition'] == 'BLOCK'
    assert row['export_category'] == 'PREREQUISITE'
    assert not row['renderable'] and not row['rendered'] and not row['satisfied']
    assert 'missing_target_vsys' in row['render_blockers']

    mapped = PANMigrationPlan(**{family: (replace(item, target_vsys='vsys2'),)})
    rendered = PANSetRenderer().render(mapped)
    assert rendered.commands and all(command.startswith('set vsys vsys2 ') for command in rendered.commands)
    assert rendered.report['summary']['command_renderable'] == rendered.report['summary']['satisfied'] == 1


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


@pytest.mark.parametrize('mapped', [False, True])
def test_cli_scope_readiness_matches_actual_commands(tmp_path, mapped):
    import json
    from click.testing import CliRunner
    from fwmigrate.main import cli

    source = tmp_path / 'source.conf'
    source.write_text('''config firewall address
edit "host"
set type ipmask
set subnet 192.0.2.1 255.255.255.255
next
end
config firewall service custom
edit "web"
set protocol TCP/UDP/SCTP
set tcp-portrange 443
next
end
config firewall schedule recurring
edit "work"
set day monday
set start 09:00
set end 17:00
next
end
''')
    output = tmp_path / 'output'
    args = ['migrate', '--input', str(source), '--output', str(output),
            '--automation-mode', 'REVIEW_ONLY']
    if mapped:
        mapping = tmp_path / 'mapping.yaml'
        mapping.write_text('vdoms:\n  root:\n    vsys: vsys2\n')
        args.extend(['--zone-map', str(mapping)])
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    report = json.loads((output / 'migration_report.json').read_text())
    commands = (output / 'palo_alto_config.set').read_text().splitlines()
    assert report['commands'] == len(commands)
    assert report['command_renderable'] == report['satisfied'] == (3 if mapped else 0)
    assert all(row['rendered'] == row['command_renderable'] == mapped for row in report['items'])
    assert all(command.startswith('set vsys vsys2 ') for command in commands)
    if not mapped:
        assert all('missing_target_vsys' in row['render_blockers'] for row in report['items'])
