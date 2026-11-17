from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
import pytest
import hashlib
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedStaticRoute
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import _v
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedDHCPServer, PlannedInterface
import json
from click.testing import CliRunner
from fwmigrate.main import cli
from dataclasses import replace
from pathlib import Path
import yaml
from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner, PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedNATRule
from fwmigrate.conversion.fortigate_to_palo_alto.planning.naming import allocate_plan_names
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedSchedule, PlannedSecurityRule
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedZone
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedService
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import build_decision_set, PANDecisionReviewState, PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements

# --- test_cli_addresses.py ---
def test_address_and_static_address_group_commands():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_object_type="address", source_name="web", target_vsys="vsys1",
                                  status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="10.0.0.10/32"),),
        address_groups=(PlannedAddressGroup(source_object_type="address_group", source_name="servers", target_vsys="vsys1",
                                            status=PANMigrationStatus.SUPPORTED, members=("web",)),),
    )

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 address web ip-netmask 10.0.0.10/32",
        "set vsys vsys1 address-group servers static [ web ]",
    )


@pytest.mark.parametrize('kind,value,valid', [
    ('ip-range', '192.0.2.50-192.0.2.1', False), ('ip-range', '192.0.2.1-192.0.2.1', True),
    ('ip-range', 'bad-192.0.2.1', False), ('ip-netmask', '192.0.2.1/99', False),
    ('ip-netmask', '::/0', False), ('ip-wildcard', '192.0.2.0/999.0.0.0', False),
    ('fqdn', 'bad name.example', False), ('fqdn', 'example.org', True), ('future', '192.0.2.1', False),
])
def test_address_values_are_validated_before_direct_rendering(kind, value, valid):
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_object_type='address', source_name='host',
        target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, address_type=kind, value=value),),
        address_groups=(PlannedAddressGroup(source_object_type='address_group', source_name='group',
            target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, members=('host',)),))
    assert bool(PANSetRenderer().render(plan).commands) == valid

# --- test_cli_compatibility.py ---
def test_documentation_baseline_never_claims_device_or_other_release_validation():
    report = PANSetRenderer().render(PANMigrationPlan()).report
    assert report['cli_compatibility'] == {
        'reference_version': '11.1', 'verification': 'DOCUMENTED_SYNTAX',
        'device_validation': 'UNVERIFIED', 'other_versions': 'UNVERIFIED',
    }


@pytest.mark.parametrize('control', ['\r', '\r\n', '\0', '\x1b', '\t', '\x7f', '\x85', '\u2028', '\u2029'])
def test_renderer_rejects_terminal_controls(control):
    with pytest.raises(ValueError, match='unsafe control character'):
        _v('description' + control + 'next command')


def test_renderer_preserves_valid_escaping_and_artifact_identity(tmp_path):
    description = 'Café "quoted" \\ path\nsecond line'
    assert _v(description) == '"Café \\"quoted\\" \\\\ path\\nsecond line"'
    plan = PANMigrationPlan(static_routes=(PlannedStaticRoute(source_object_type='static_route', source_name='1',
        status=PANMigrationStatus.SUPPORTED, virtual_router='vr', destination='192.0.2.0/24',
        nexthop_type='discard', description=description),))
    renderer = PANSetRenderer()
    artifact = renderer.render(plan)
    renderer.write_files(artifact, tmp_path)
    exported = (tmp_path / 'palo_alto_config.set').read_text(encoding='utf-8')
    assert exported == '\n'.join(artifact.commands)
    assert artifact.report['commands'] == len(artifact.commands)
    assert artifact.report['command_sha256'] == hashlib.sha256(exported.encode()).hexdigest()

# --- test_cli_dhcp.py ---
def test_dhcp_commands_render_after_interface_ownership_in_device_scope():
    interface = PlannedInterface(
        source_vdom="root",
        source_kind="interface",
        source_object_type="interface",
        source_name="lan",
        target_vsys="vsys1",
        target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED,
        interface_family="ethernet",
        virtual_router="vr-main",
    )
    dhcp = PlannedDHCPServer(
        source_vdom="root",
        source_kind="dhcp_server",
        source_object_type="dhcp_server",
        source_name="1",
        target_vsys="vsys1",
        target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED,
        interface="ethernet1/3",
        mode="enabled",
        lease_type="timeout",
        lease_timeout=3600,
        gateway="10.0.0.1",
        subnet_mask="255.255.255.0",
        dns_primary="10.0.0.2",
        dns_secondary="10.0.0.3",
        ip_pools=("10.0.0.10-10.0.0.50",),
    )

    rendered = PANSetRenderer().render(PANMigrationPlan(
        interfaces=(interface,),
        dhcp_servers=(dhcp,),
    ))

    dhcp_commands = (
        "set network dhcp interface ethernet1/3 server mode enabled",
        "set network dhcp interface ethernet1/3 server option lease timeout 3600",
        "set network dhcp interface ethernet1/3 server option gateway 10.0.0.1",
        "set network dhcp interface ethernet1/3 server option subnet-mask 255.255.255.0",
        "set network dhcp interface ethernet1/3 server option dns primary 10.0.0.2",
        "set network dhcp interface ethernet1/3 server option dns secondary 10.0.0.3",
        "set network dhcp interface ethernet1/3 server ip-pool [ 10.0.0.10-10.0.0.50 ]",
    )
    assert rendered.commands[-len(dhcp_commands):] == dhcp_commands
    assert rendered.commands.index("set network virtual-router vr-main interface [ ethernet1/3 ]") < (
        rendered.commands.index(dhcp_commands[0])
    )
    item = next(item for item in rendered.report["items"] if item["source_object_type"] == "dhcp_server")
    assert item["rendered"] is True
    assert item["commands"] == list(dhcp_commands)


def test_unlimited_dhcp_lease_renders_without_timeout():
    interface = PlannedInterface(
        source_vdom="root", source_object_type="interface", source_name="lan",
        target_vsys="vsys1", target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED, interface_family="ethernet",
        virtual_router="vr-main",
    )
    dhcp = PlannedDHCPServer(
        source_vdom="root", source_object_type="dhcp_server", source_name="1",
        target_vsys="vsys1", target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED, interface="ethernet1/3",
        mode="disabled", lease_type="unlimited",
        ip_pools=("10.0.0.10-10.0.0.50",),
    )
    commands = PANSetRenderer().render(
        PANMigrationPlan(interfaces=(interface,), dhcp_servers=(dhcp,))
    ).commands
    assert "set network dhcp interface ethernet1/3 server option lease unlimited" in commands
    assert not any("lease timeout" in command for command in commands)

# --- test_cli_interface_zones.py ---
@pytest.mark.parametrize('mapped_zones', [True, False])
def test_cli_plans_interface_zones_only_from_explicit_mappings(tmp_path, mapped_zones):
    source = tmp_path / 'source.conf'
    source.write_text('''config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit wan
set type physical
set ip 203.0.113.1 255.255.255.0
next
end
config firewall policy
edit 1
set name outbound
set srcintf lan
set dstintf wan
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
set nat enable
next
end
''')
    before = source.read_bytes()
    mapping = tmp_path / 'mapping.yaml'
    import yaml

    interfaces = {'lan': {'target_interface': 'ethernet1/1'}, 'wan': {'target_interface': 'ethernet1/2'}}
    if mapped_zones:
        interfaces['lan']['target_zone'] = 'trust'
        interfaces['wan']['target_zone'] = 'untrust'
    mapping.write_text(yaml.safe_dump({'vdoms': {'root': {'vsys': 'vsys2', 'virtual_router': 'VR'}},
                                      'interfaces': {'root': interfaces}}))
    output = tmp_path / 'output'
    response = CliRunner().invoke(cli, ['migrate', '--input', str(source), '--output', str(output),
        '--zone-map', str(mapping), '--automation-mode', 'REVIEW_ONLY'])
    assert response.exit_code == 0, response.output
    report = json.loads((output / 'migration_report.json').read_text())
    commands = (output / 'palo_alto_config.set').read_text().splitlines()
    zones = [row for row in report['items'] if row['source_object_type'] == 'zone']
    if mapped_zones:
        assert report['plan_status'] == 'READY'
        assert len(zones) == 2 and all(row['rendered'] for row in zones)
        assert 'set vsys vsys2 zone trust network layer3 [ ethernet1/1 ]' in commands
        assert 'set vsys vsys2 zone untrust network layer3 [ ethernet1/2 ]' in commands
        assert any('rulebase security rules outbound action allow' in command for command in commands)
        assert any('source-translation dynamic-ip-and-port interface-address interface ethernet1/2' in command
                   for command in commands)
        first_rule = next(index for index, command in enumerate(commands) if ' rulebase ' in command)
        assert all(index < first_rule for index, command in enumerate(commands) if ' zone ' in command)
    else:
        assert report['plan_status'] != 'READY'
        assert not zones and not any(' rulebase ' in command for command in commands)
    assert report['commands'] == len(commands)
    assert source.read_bytes() == before

# --- test_cli_interfaces.py ---
def test_physical_interface_renders_device_import_and_router_membership_in_order():
    plan = PANMigrationPlan(interfaces=(
        PlannedInterface(
            source_vdom="root",
            source_kind="interface",
            source_object_type="interface",
            source_name="port1",
            target_vsys="vsys1",
            target_name="ethernet1/1",
            status=PANMigrationStatus.SUPPORTED,
            interface_family="ethernet",
            ipv4_addresses=("192.0.2.1/24",),
            virtual_router="vr-main",
        ),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set network interface ethernet ethernet1/1 layer3",
        "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24",
        "set vsys vsys1 import network interface [ ethernet1/1 ]",
        "set network virtual-router vr-main interface [ ethernet1/1 ]",
    )


def test_vlan_subinterface_renders_under_explicit_mapped_parent():
    plan = PANMigrationPlan(interfaces=(
        PlannedInterface(
            source_vdom="root",
            source_kind="interface",
            source_object_type="interface",
            source_name="vlan100",
            target_vsys="vsys1",
            target_name="ethernet1/1.100",
            status=PANMigrationStatus.SUPPORTED,
            interface_family="ethernet",
            parent="ethernet1/1",
            tag=100,
            ipv4_addresses=("10.0.0.1/24",),
            virtual_router="vr-main",
        ),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set network interface ethernet ethernet1/1 layer3 units ethernet1/1.100",
        "set network interface ethernet ethernet1/1 layer3 units ethernet1/1.100 tag 100",
        "set network interface ethernet ethernet1/1 layer3 units ethernet1/1.100 ip 10.0.0.1/24",
        "set vsys vsys1 import network interface [ ethernet1/1.100 ]",
        "set network virtual-router vr-main interface [ ethernet1/1.100 ]",
    )


def loopback(**changes):
    return PlannedInterface(source_vdom='root', source_kind='interface', source_object_type='interface',
        source_name='lo', target_vsys='vsys1', target_name='loopback.1', status=PANMigrationStatus.SUPPORTED,
        interface_family='loopback', ipv4_addresses=('192.0.2.1/32',), virtual_router='vr-main', **changes)


def test_loopback_uses_verified_pan_os_11_1_units_path():
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=(loopback(),))).commands == (
        'set network interface loopback units loopback.1',
        'set network interface loopback units loopback.1 ip 192.0.2.1/32',
        'set vsys vsys1 import network interface [ loopback.1 ]',
        'set network virtual-router vr-main interface [ loopback.1 ]',
    )


@pytest.mark.parametrize('changes', [dict(target_name='loopback.0'), dict(target_vsys=None),
    dict(virtual_router=None), dict(ipv4_addresses=('invalid/32',)), dict(ipv4_addresses=('192.0.2.1/24',)), dict(parent='ethernet1/1', tag=10)])
def test_invalid_loopback_plan_never_renders(changes):
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=(replace(loopback(), **changes),))).commands == ()


def test_duplicate_loopbacks_are_blocked_across_vsys():
    items = (loopback(), replace(loopback(), source_vdom='other', target_vsys='vsys2'))
    assert PANSetRenderer().render(PANMigrationPlan(interfaces=items)).commands == ()

# --- test_cli_mvp_golden.py ---
FIXTURES = Path(__file__).parents[2] / "fixtures" / "fortigate"


def test_fortigate_mvp_pipeline_matches_exact_set_golden():
    analysis = FortiGateSourceReporter().analyze_source((FIXTURES / "palo_alto_mvp.conf").read_text())
    options = PANMigrationOptions(**yaml.safe_load((FIXTURES / "palo_alto_mvp_mapping.yaml").read_text()))
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options)
    validation = validate_plan(plan)

    assert any(
        issue.code == "missing_nat_zone" and issue.source.source_name == "web-vip"
        for issue in validation.issues
    )
    assert ("nat_rule", "vsys1", "web-vip") not in validation.renderable_item_keys
    commands = PANSetRenderer().render(plan, validation).commands
    expected = tuple((FIXTURES / "palo_alto_mvp_expected.set").read_text().splitlines())
    assert commands == expected

# --- test_cli_nat.py ---
def test_snat_pool_interface_address_and_dnat_commands():
    plan = PANMigrationPlan(nat_rules=(
        PlannedNATRule(source_object_type="nat_rule", source_name="snat-pool", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("untrust",),
                       source_addresses=("clients",), destination_addresses=("any",), service="https",
                       to_interface="ethernet1/2", source_translation_type="dynamic-ip-and-port",
                       translated_addresses=("203.0.113.10", "203.0.113.11")),
        PlannedNATRule(source_object_type="nat_rule", source_name="snat-interface", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("untrust",),
                       source_interface_address=True, source_translation_type="dynamic-ip-and-port", to_interface="ethernet1/2"),
        PlannedNATRule(source_object_type="nat_rule", source_name="dnat", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, from_zones=("untrust",), to_zones=("trust",),
                       source_addresses=("any",), destination_addresses=("198.51.100.10",), service="https",
                       to_interface="ethernet1/1", destination_translated_address="10.0.0.10",
                       destination_translated_port="8443"),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 rulebase nat rules snat-pool nat-type ipv4",
        "set vsys vsys1 rulebase nat rules snat-pool from [ trust ]",
        "set vsys vsys1 rulebase nat rules snat-pool to [ untrust ]",
        "set vsys vsys1 rulebase nat rules snat-pool source [ clients ]",
        "set vsys vsys1 rulebase nat rules snat-pool destination [ any ]",
        "set vsys vsys1 rulebase nat rules snat-pool service https",
        "set vsys vsys1 rulebase nat rules snat-pool to-interface ethernet1/2",
        "set vsys vsys1 rulebase nat rules snat-pool source-translation dynamic-ip-and-port translated-address [ 203.0.113.10 203.0.113.11 ]",
        "set vsys vsys1 rulebase nat rules snat-interface nat-type ipv4",
        "set vsys vsys1 rulebase nat rules snat-interface from [ trust ]",
        "set vsys vsys1 rulebase nat rules snat-interface to [ untrust ]",
        "set vsys vsys1 rulebase nat rules snat-interface to-interface ethernet1/2",
        "set vsys vsys1 rulebase nat rules snat-interface source-translation dynamic-ip-and-port interface-address interface ethernet1/2",
        "set vsys vsys1 rulebase nat rules dnat nat-type ipv4",
        "set vsys vsys1 rulebase nat rules dnat from [ untrust ]",
        "set vsys vsys1 rulebase nat rules dnat to [ trust ]",
        "set vsys vsys1 rulebase nat rules dnat source [ any ]",
        "set vsys vsys1 rulebase nat rules dnat destination [ 198.51.100.10 ]",
        "set vsys vsys1 rulebase nat rules dnat service https",
        "set vsys vsys1 rulebase nat rules dnat to-interface ethernet1/1",
        "set vsys vsys1 rulebase nat rules dnat destination-translation translated-address 10.0.0.10",
        "set vsys vsys1 rulebase nat rules dnat destination-translation translated-port 8443",
    )


def test_interface_address_nat_requires_an_explicit_interface():
    item = PlannedNATRule(source_object_type="nat_rule", source_name="incomplete", target_vsys="vsys1",
                          status=PANMigrationStatus.SUPPORTED, from_zones=("any",), to_zones=("any",),
                          source_interface_address=True, source_translation_type="dynamic-ip-and-port")
    rendered = PANSetRenderer().render(PANMigrationPlan(nat_rules=(item,)))
    assert rendered.commands == ()
    assert "missing_nat_interface" in rendered.report["items"][0]["render_blockers"]

# --- test_cli_routing.py ---
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

# --- test_cli_schedules.py ---
def test_weekly_and_one_time_schedule_commands():
    plan = PANMigrationPlan(schedules=(
        PlannedSchedule(source_object_type="schedule", source_name="work", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED, schedule_type="recurring",
                        weekly=(("monday", "08:00", "17:00"), ("friday", "08:30", "16:00"))),
        PlannedSchedule(source_object_type="schedule", source_name="holiday", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED, schedule_type="one-time",
                        non_recurring=(("2026/12/25@00:00", "2026/12/26@00:00"),)),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 schedule work schedule-type recurring",
        "set vsys vsys1 schedule work schedule-type recurring weekly monday [ 08:00-17:00 ]",
        "set vsys vsys1 schedule work schedule-type recurring weekly friday [ 08:30-16:00 ]",
        "set vsys vsys1 schedule holiday schedule-type non-recurring [ 2026/12/25@00:00-2026/12/26@00:00 ]",
    )


@pytest.mark.parametrize('kind,settings', [
    ('recurring', 'set day none\nset start 08:00\nset end 17:00'),
    ('recurring', 'set day monday\nset start 17:00\nset end 08:00'),
    ('recurring', 'set day monday\nset start 00:00\nset end 00:00'),
    ('recurring', 'set day monday\nset start 08:00\nset end 25:00'),
    ('recurring', 'set day monday\nset start 08:00\nset end 17:00\nset future-setting enable'),
    ('onetime', 'set start 02:00 2026/12/25\nset end 01:00 2026/12/25'),
    ('onetime', 'set start 01:00 2026/02/30\nset end 02:00 2026/02/30'),
    ('onetime', 'set start 2026/12/25 01:00\nset end 2026/12/25 02:00'),
    ('onetime', 'set start 01:00 2026/12/25\nset end 02:00 2026/12/25\nset start-utc 123'),
])
def test_unrepresented_native_schedule_values_are_blocked_without_changing_source(kind, settings):
    analysis = FortiGateSourceReporter().analyze_source(
        f'config firewall schedule {kind}\nedit window\n{settings}\nnext\nend\n')
    source = analysis.extracted.config
    original = source.model_dump()
    plan = FortiGateToPaloAltoPlanner().plan(source, analysis.derived,
        PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    assert plan.schedules[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert plan.schedules[0].warnings
    assert PANSetRenderer().render(plan).commands == ()
    assert source.model_dump() == original


@pytest.mark.parametrize('settings', [
    {'schedule_type': 'recurring', 'weekly': (('none', '08:00', '17:00'),)},
    {'schedule_type': 'recurring', 'weekly': (('monday', '17:00', '08:00'),)},
    {'schedule_type': 'one-time', 'non_recurring': (('01:00 2026/12/25', '02:00 2026/12/25'),)},
    {'schedule_type': 'one-time', 'non_recurring': (('2026/12/25@02:00', '2026/12/25@01:00'),)},
])
def test_direct_plan_validation_blocks_invalid_schedules_and_dependent_rules(settings):
    schedule = PlannedSchedule(source_object_type='schedule', source_name='window', target_vsys='vsys1',
        status=PANMigrationStatus.SUPPORTED, **settings)
    rule = PlannedSecurityRule(source_object_type='security_rule', source_name='scheduled', target_vsys='vsys1',
        status=PANMigrationStatus.SUPPORTED,
        from_zones=('any',), to_zones=('any',), sources=('0.0.0.0/0',), destinations=('0.0.0.0/0',),
        services=('any',), applications=('any',), action='allow', schedule='window')
    plan = PANMigrationPlan(schedules=(schedule,), security_rules=(rule,))
    valid = replace(schedule, schedule_type='recurring', weekly=(('monday', '08:00', '17:00'),), non_recurring=())
    assert any('rules scheduled ' in command for command in PANSetRenderer().render(replace(plan, schedules=(valid,))).commands)
    assert not any('schedule window ' in command or 'rulebase security' in command
                   for command in PANSetRenderer().render(plan).commands)

# --- test_cli_scope.py ---
def test_vsys_switching_keeps_duplicate_names_scoped_and_routes_at_device_scope():
    plan = PANMigrationPlan(
        addresses=(
            PlannedAddress(source_vdom="root", source_object_type="address", source_name="shared",
                           target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                           address_type="ip-netmask", value="10.0.0.1/32"),
            PlannedAddress(source_vdom="vdom-a", source_object_type="address", source_name="shared",
                           target_vsys="vsys2", status=PANMigrationStatus.SUPPORTED,
                           address_type="ip-netmask", value="10.0.0.2/32"),
        ),
        security_rules=(
            PlannedSecurityRule(applications=("any",), source_vdom="root", source_object_type="security_rule", source_name="root-rule",
                                target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                                from_zones=("any",), to_zones=("any",), sources=("shared",),
                                destinations=("any",), services=("any",), action="allow"),
            PlannedSecurityRule(applications=("any",), source_vdom="vdom-a", source_object_type="security_rule", source_name="vdom-rule",
                                target_vsys="vsys2", status=PANMigrationStatus.SUPPORTED,
                                from_zones=("any",), to_zones=("any",), sources=("shared",),
                                destinations=("any",), services=("any",), action="deny"),
        ),
        static_routes=(PlannedStaticRoute(source_vdom="vdom-a", source_object_type="static_route",
                                          source_name="default", target_vsys="vsys2",
                                          status=PANMigrationStatus.SUPPORTED, virtual_router="default",
                                          destination="0.0.0.0/0", nexthop="192.0.2.1"),),
    )

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 address shared ip-netmask 10.0.0.1/32",
        "set vsys vsys1 rulebase security rules root-rule from [ any ]",
        "set vsys vsys1 rulebase security rules root-rule to [ any ]",
        "set vsys vsys1 rulebase security rules root-rule source [ shared ]",
        "set vsys vsys1 rulebase security rules root-rule destination [ any ]",
        "set vsys vsys1 rulebase security rules root-rule service [ any ]",
        "set vsys vsys1 rulebase security rules root-rule application [ any ]",
        "set vsys vsys1 rulebase security rules root-rule action allow",
        "set vsys vsys2 address shared ip-netmask 10.0.0.2/32",
        "set vsys vsys2 rulebase security rules vdom-rule from [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule to [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule source [ shared ]",
        "set vsys vsys2 rulebase security rules vdom-rule destination [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule service [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule application [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule action deny",
        "set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0",
        "set network virtual-router default routing-table ip static-route default nexthop ip-address 192.0.2.1",
    )

# --- test_cli_security_rules.py ---
def test_security_rule_match_flags_and_actions():
    plan = PANMigrationPlan(
        zones=(
            PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED),
            PlannedZone(source_object_type="zone", source_name="untrust", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED),
        ),
        schedules=(PlannedSchedule(source_object_type="schedule", source_name="work", target_vsys="vsys1",
                                   status=PANMigrationStatus.SUPPORTED, schedule_type="recurring",
                                   weekly=(("monday", "08:00", "17:00"),)),),
        security_rules=(
        PlannedSecurityRule(applications=("any",), source_object_type="security_rule", source_name="allow-web", target_vsys="vsys1",
                            status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("untrust",),
                            sources=("any",), destinations=("any",), services=("any",), schedule="work",
                            negate_source=True, negate_destination=True, disabled=True,
                            description="web access", action="allow"),
        ),
    )

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 schedule work schedule-type recurring",
        "set vsys vsys1 schedule work schedule-type recurring weekly monday [ 08:00-17:00 ]",
        "set vsys vsys1 rulebase security rules allow-web from [ trust ]",
        "set vsys vsys1 rulebase security rules allow-web to [ untrust ]",
        "set vsys vsys1 rulebase security rules allow-web source [ any ]",
        "set vsys vsys1 rulebase security rules allow-web destination [ any ]",
        "set vsys vsys1 rulebase security rules allow-web service [ any ]",
        "set vsys vsys1 rulebase security rules allow-web application [ any ]",
        "set vsys vsys1 rulebase security rules allow-web schedule work",
        "set vsys vsys1 rulebase security rules allow-web negate-source yes",
        "set vsys vsys1 rulebase security rules allow-web negate-destination yes",
        "set vsys vsys1 rulebase security rules allow-web disabled yes",
        'set vsys vsys1 rulebase security rules allow-web description "web access"',
        "set vsys vsys1 rulebase security rules allow-web action allow",
    )


def test_incomplete_hand_built_rule_is_blocked_without_renderer_fallback():
    rule = PlannedSecurityRule(source_object_type='security_rule', source_name='incomplete', target_vsys='vsys1',
        status=PANMigrationStatus.SUPPORTED, from_zones=('any',), to_zones=('any',), sources=('any',),
        destinations=('any',), services=('any',), action='allow')
    plan = PANMigrationPlan(security_rules=(rule,))
    assert any(issue.code == 'missing_rule_applications' for issue in validate_plan(plan).issues)
    assert not PANSetRenderer().render(plan).commands


@pytest.mark.parametrize('services,applications,supported', [
    (['ALL'], ('any',), True), (['HTTP'], ('any',), True), (['HTTPS'], ('any',), True),
    (['DNS'], ('any',), True), (['custom'], ('any',), True), (['PING'], ('ping',), True),
    (['PING', 'HTTP'], ('any',), False),
])
def test_planner_explicit_application_matching(services, applications, supported):
    from types import SimpleNamespace
    from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import plan_policies
    from fwmigrate.vendors.fortigate.model.source import FGConfig
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    source = FGConfig(policies=[FGPolicy(policy_id=1, srcintf=['any'], dstintf=['any'],
        srcaddr=['all'], dstaddr=['all'], service=services, action='accept', schedule='always')])
    derived = SimpleNamespace(services=SimpleNamespace(services=[SimpleNamespace(vdom='root', name='custom')], groups=[]))
    rule = plan_policies(source, PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}), derived)[0]
    assert rule.applications == applications
    assert (rule.status is PANMigrationStatus.SUPPORTED) == supported

# --- test_cli_services.py ---
def test_tcp_destination_tcp_source_and_udp_service_commands():
    plan = PANMigrationPlan(services=(
        PlannedService(source_object_type="service", source_name="https", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="tcp", destination_port="443"),
        PlannedService(source_object_type="service", source_name="tcp-source", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="tcp", source_port="1024-65535",
                       destination_port="443"),
        PlannedService(source_object_type="service", source_name="dns", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="udp", destination_port="53"),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 service https protocol tcp",
        "set vsys vsys1 service https protocol tcp port 443",
        "set vsys vsys1 service tcp-source protocol tcp",
        "set vsys vsys1 service tcp-source protocol tcp port 443",
        "set vsys vsys1 service tcp-source protocol tcp source-port 1024-65535",
        "set vsys vsys1 service dns protocol udp",
        "set vsys vsys1 service dns protocol udp port 53",
    )


@pytest.mark.parametrize('port,valid', [('70000', False), ('65536', False), ('-1', False),
    ('443,,8443', False), ('100-1', False), ('0', True), ('65535', True),
    ('0-65535', True), ('443,8000-8080', True), ('', False)])
@pytest.mark.parametrize('field', ['destination_port', 'source_port'])
def test_port_expressions_are_validated_before_direct_rendering(port, valid, field):
    fields = {'destination_port': '443', field: port}
    plan = PANMigrationPlan(services=(PlannedService(source_object_type='service', source_name='web',
        target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, protocol='tcp', **fields),))
    assert bool(PANSetRenderer().render(plan).commands) == valid


def test_extremely_long_port_number_fails_closed_without_crashing():
    plan = PANMigrationPlan(services=(PlannedService(source_object_type='service', source_name='web',
        target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, protocol='tcp', destination_port='9' * 5000),))
    assert not PANSetRenderer().render(plan).commands

# --- test_cli_zones.py ---
@pytest.mark.parametrize('named_second', [False, True])
@pytest.mark.parametrize('missing_member', [False, True])
def test_zone_consolidation_retains_members_decisions_and_blockers(named_second, missing_member):
    source = FGConfig(interfaces=[FGInterface(name=name, type='physical') for name in ('lan1', 'lan2')],
        zones=[FGZone(name='first', members=['lan1'])] + ([FGZone(name='second', members=['lan2'])] if named_second else []),
        policies=[FGPolicy(policy_id=1, srcintf=['first'], dstintf=['any'], srcaddr=['all'], dstaddr=['all'],
            service=['ALL'], action='accept', schedule='always')])
    original = source.model_dump()
    derived = build_derived_views(source)
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'vr'}},
        interfaces={'root': {'lan1': {'target_interface': 'ethernet1/1'},
            'lan2': {'target_interface': None if missing_member else 'ethernet1/2', 'target_zone': 'trust'}}},
        zones={'root': {'first': {'target_zone': 'trust'}, 'second': {'target_zone': 'trust'}}})
    plan = FortiGateToPaloAltoPlanner().plan(source, derived, options, include_configuration=True)
    assert len(plan.zones) == 1
    zone = plan.zones[0]
    assert {ref.source_name for ref in zone.source_contributors} == {'first', 'second' if named_second else 'lan2'}
    decisions = build_decision_set(source, derived, build_mapping_requirements(source, derived, include_configuration=True))
    index = build_plan_dependency_index(plan, decisions)
    for ref in zone.source_contributors:
        keys = [row.key for row in decisions.decisions if row.source_kind == ref.source_kind and row.source_name == ref.source_name]
        assert keys and all(item_key(zone) in index.item_keys_by_decision[key] for key in keys)
    artifact = PANSetRenderer().render(plan)
    assert zone.status is PANMigrationStatus.MANUAL_REVIEW
    assert not any(' zone trust ' in command or 'rulebase security' in command for command in artifact.commands)
    if not missing_member:
        assert zone.interfaces == ('ethernet1/1', 'ethernet1/2')
        assert any('intra-zone' in warning for warning in zone.warnings)
    assert source.model_dump() == original
    coverage = build_migration_coverage(source, plan=plan, options=options)
    assert not any(row['source_kind'] == 'zone' for row in coverage['unplanned'])


def test_additive_zone_requires_every_contributor_approval():
    from fwmigrate.conversion.fortigate_to_palo_alto.models import MigrationSourceRef
    from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecision
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import assess_target_plan, PANRenderDisposition
    zone = PlannedZone(source_vdom='root', source_kind='zone', source_object_type='zone', source_name='first',
        target_vsys='vsys1', target_name='trust', status=PANMigrationStatus.SUPPORTED,
        source_contributors=tuple(MigrationSourceRef('root', 'zone', name) for name in ('first', 'second')))
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision('root', 'zone', name, 'target_zone', value='trust',
        review_state=PANDecisionReviewState.CONFIRMED, approved_operation='CONFIGURE') for name in ('first', 'second')))
    plan = PANMigrationPlan(zones=(zone,))
    classification = ({'family': 'zone', 'source_vdom': 'root', 'source_kind': 'zone', 'source_name': 'first',
        'target_vsys': 'vsys1', 'target_name': 'trust', 'status': 'ADDITIVE'},)
    for approved, expected in ((decisions, PANRenderDisposition.CONFIGURE),
                              (replace(decisions, decisions=decisions.decisions[:1]), PANRenderDisposition.BLOCK)):
        dispositions, _ = assess_target_plan(plan, classification, (), approved, build_plan_dependency_index(plan, approved))
        assert dispositions[item_key(zone)] is expected


def test_zones_from_different_vdoms_are_not_consolidated():
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.topology import plan_topology
    from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
    source = FGConfig(zones=[FGZone(vdom=vdom, name='inside') for vdom in ('a', 'b')])
    options = PANMigrationOptions(vdoms={vdom: {'vsys': 'vsys1'} for vdom in ('a', 'b')},
        zones={vdom: {'inside': {'target_zone': 'trust'}} for vdom in ('a', 'b')})
    zones = plan_topology(source, build_derived_views(source), options)
    assert len(zones) == 2
    plan = PANMigrationPlan(zones=zones)
    assert any(issue.code == 'duplicate_target_name' for issue in validate_plan(plan).issues)
    assert not PANSetRenderer().render(plan).commands


def test_zone_interface_membership_commands():
    plan = PANMigrationPlan(zones=(
        PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1",
                    status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1", "ethernet1/3")),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 zone trust network layer3 [ ethernet1/1 ethernet1/3 ]",
    )
