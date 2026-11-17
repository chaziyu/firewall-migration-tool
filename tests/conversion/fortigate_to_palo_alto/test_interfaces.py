from fwmigrate.conversion.fortigate_to_palo_alto.planning.interfaces import plan_interfaces
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.interface import FGInterfaceSecondaryIP
from fwmigrate.vendors.fortigate.model.source import FGConfig
import pytest
from dataclasses import replace
from copy import deepcopy
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.target.profile import parse_conversion_settings
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import assess_target_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedManagementProfile
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_object_reuse import classify_target_object_reuse
from fwmigrate.vendors.palo_alto.model.management_profile import MANAGEMENT_PROTOCOLS
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage

# --- test_interfaces.py ---
def test_metadata_secondary_addresses_and_explicit_existing_management_profile():
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.cli_paths import interface
    source = FGConfig(interfaces=[FGInterface(name='port1', ip='192.0.2.1/24', allowaccess=['https'],
        secondary_ips=[FGInterfaceSecondaryIP(ip='198.51.100.1/24')], raw_extra={'snmp-index': '1', 'secondary-IP': 'enable'})])
    options = _options({'port1': {'target_interface': 'ethernet1/1'}})
    blocked, = plan_interfaces(source, options)
    assert blocked.status is PANMigrationStatus.MANUAL_REVIEW
    planned, = plan_interfaces(source, replace(options, conversion_settings={'management_profiles': {'root/port1': 'restricted-admin'}}))
    assert planned.status is PANMigrationStatus.SUPPORTED
    assert planned.ipv4_addresses == ('192.0.2.1/24', '198.51.100.1/24')
    assert any(path[-2:] == ('interface-management-profile', 'restricted-admin') for path in interface(planned))
    source.interfaces[0].raw_extra['src-check'] = 'disable'
    assert plan_interfaces(source, options)[0].status is PANMigrationStatus.MANUAL_REVIEW


def _options(interfaces):
    return PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "vr-main"}},
        interfaces={"root": interfaces},
    )


def test_management_groups_preserve_vdom_protocol_sets_and_monitoring_metadata():
    from fwmigrate.conversion.fortigate_to_palo_alto.target.profile import management_profile_groups
    source = FGConfig(interfaces=[
        FGInterface(name='a', allowaccess=['ping', 'ssh'], raw_extra={'monitor-bandwidth': 'enable'}),
        FGInterface(name='b', allowaccess=['ssh', 'ping']),
        FGInterface(name='c', allowaccess=['https']),
        FGInterface(name='a', vdom='blue', allowaccess=['ssh', 'ping']),
    ])
    groups = management_profile_groups(source)
    assert len(groups) == 3
    assert next(group for group in groups if group['identity'] == 'root/ping,ssh')['member_keys'] == ['root/a', 'root/b']
    options = replace(_options({'a': {'target_interface': 'ethernet1/1'}}),
        conversion_settings={'management_profiles': {'root/a': 'reviewed'}})
    interface, = plan_interfaces(source, options)
    assert interface.status is PANMigrationStatus.SUPPORTED
    assert source.interfaces[0].raw_extra == {'monitor-bandwidth': 'enable'}


def test_static_ethernet_mapping_becomes_executable_interface():
    source = FGConfig(interfaces=[
        FGInterface(name="port1", ip="192.0.2.1 255.255.255.0"),
    ])

    planned = plan_interfaces(
        source,
        _options({"port1": {"target_interface": "ethernet1/1"}}),
    )

    assert len(planned) == 1
    item = planned[0]
    assert item.status is PANMigrationStatus.SUPPORTED
    assert item.target_name == "ethernet1/1"
    assert item.target_vsys == "vsys1"
    assert item.virtual_router == "vr-main"
    assert item.parent is None
    assert item.ipv4_addresses == ("192.0.2.1/24",)


def test_vlan_mapping_requires_explicit_parent_and_vlan_id():
    source = FGConfig(interfaces=[
        FGInterface(name="port1"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100, ip="10.0.0.1/24"),
    ])
    planned = plan_interfaces(
        source,
        _options({
            "port1": {"target_interface": "ethernet1/1"},
            "vlan100": {"target_interface": "ethernet1/1.100"},
        }),
    )
    by_name = {item.source_name: item for item in planned}

    assert by_name["port1"].status is PANMigrationStatus.SUPPORTED
    assert by_name["vlan100"].status is PANMigrationStatus.SUPPORTED
    assert by_name["vlan100"].parent == "ethernet1/1"
    assert by_name["vlan100"].tag == 100
    assert by_name["vlan100"].ipv4_addresses == ("10.0.0.1/24",)


def test_dynamic_or_unknown_interface_semantics_fail_closed():
    source = FGConfig(interfaces=[
        FGInterface(name="wan", mode="dhcp"),
        FGInterface(name="agg1", type="aggregate", members=["port1", "port2"]),
    ])
    planned = plan_interfaces(
        source,
        _options({
            "wan": {"target_interface": "ethernet1/1"},
            "agg1": {"target_interface": "ae1"},
        }),
    )
    by_name = {item.source_name: item for item in planned}

    assert by_name["wan"].status is PANMigrationStatus.MANUAL_REVIEW
    assert any("dynamic interface mode" in warning for warning in by_name["wan"].warnings)
    assert by_name["agg1"].status is PANMigrationStatus.MANUAL_REVIEW
    assert any("explicit supported lacp-mode" in warning for warning in by_name["agg1"].warnings)


def test_interface_planning_never_infers_missing_ownership():
    source = FGConfig(interfaces=[FGInterface(name="port1", ip="192.0.2.1/24")])
    planned = plan_interfaces(
        source,
        PANMigrationOptions(interfaces={"root": {
            "port1": {"target_interface": "ethernet1/1"},
        }}),
    )

    assert planned[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert any("vsys mapping" in warning.lower() for warning in planned[0].warnings)
    assert any("virtual-router mapping" in warning.lower() for warning in planned[0].warnings)


@pytest.mark.parametrize('extra', [{}, {'allowaccess': ['ping']}, {'raw_extra': {'mtu': 1400}}, {'mode': 'dhcp'}])
def test_loopback_planning_preserves_only_the_supported_explicit_subset(extra):
    config = FGConfig(interfaces=[FGInterface(name='lo', type='loopback', ip='192.0.2.1/32', **extra)])
    item, = plan_interfaces(config, _options({'lo': {'target_interface': 'loopback.1'}}))
    assert item.interface_family == 'loopback'
    assert item.ipv4_addresses == ('192.0.2.1/32',)
    assert (item.status is PANMigrationStatus.SUPPORTED) == (not extra)


@pytest.mark.parametrize('name', ['loopback.0', 'loopback.10000', 'ethernet1/1', 'loopback.x'])
def test_loopback_identifier_is_validated(name):
    config = FGConfig(interfaces=[FGInterface(name='lo', type='loopback')])
    item, = plan_interfaces(config, _options({'lo': {'target_interface': name}}))
    assert item.status is PANMigrationStatus.MANUAL_REVIEW


def test_loopback_bare_address_does_not_infer_a_host_mask():
    config = FGConfig(interfaces=[FGInterface(name='lo', type='loopback', ip='192.0.2.1')])
    item, = plan_interfaces(config, _options({'lo': {'target_interface': 'loopback.1'}}))
    assert item.status is PANMigrationStatus.MANUAL_REVIEW
    assert not item.ipv4_addresses

# --- test_aggregate_interfaces.py ---
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


def test_unmapped_aggregate_never_turns_its_members_into_standalone_interfaces():
    config = source()
    config.interfaces.pop()  # No VLAN; member mappings must still fail closed.
    items = plan_interfaces(config, options(bond={}))
    assert {item.source_name for item in items} == {'port1', 'port2'}
    assert all(item.status is PANMigrationStatus.MANUAL_REVIEW for item in items)
    assert not PANSetRenderer().render(PANMigrationPlan(interfaces=items)).commands

# --- test_management_profiles.py ---
SOURCE = '''config system interface
edit port1
set type physical
set ip 192.0.2.1 255.255.255.0
set allowaccess ping ssh
next
end
'''


def planned():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
        interfaces={'root': {'port1': {'target_interface': 'ethernet1/1', 'target_zone': 'outside'}}},
        conversion_settings={'generated_management_profiles': {'root/ping,ssh': {'permitted_ips': ['192.0.2.0/24']}}})
    return FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)


def test_reviewed_profile_precedes_attachment_and_has_explicit_restrictions():
    plan = planned()
    profile, = plan.management_profiles
    assert profile.target_vsys is None and profile.status is PANMigrationStatus.SUPPORTED
    assert plan.interfaces[0].management_profile == profile.target_name
    commands = PANSetRenderer().render(plan).commands
    prefix = f'set network profiles interface-management-profile {profile.target_name}'
    assert prefix + ' permitted-ip 192.0.2.0/24' in commands
    assert prefix + ' https no' in commands
    assert prefix + ' ssh yes' in commands
    attached = f'set network interface ethernet ethernet1/1 layer3 interface-management-profile {profile.target_name}'
    assert commands.index(prefix + ' permitted-ip 192.0.2.0/24') < commands.index(attached)
    assert any(row['source_object_type'] == 'management_profile' and row['rendered'] for row in PANSetRenderer().render(plan).report['items'])


@pytest.mark.parametrize('values', [[], ['invalid'], ['192.0.2.1/24'], [None], '192.0.2.0/24'])
def test_permitted_networks_must_be_explicit_valid_cidrs(values):
    with pytest.raises(ValueError):
        parse_conversion_settings({'generated_management_profiles': {'root/ping': {'permitted_ips': values}}})


@pytest.mark.parametrize(('field', 'message'), [
    ('excluded_interfaces', 'Excluded interfaces must preserve VDOM/name identity'),
    ('existing_vpns', 'Existing VPN prerequisites must preserve VDOM/name identity'),
])
@pytest.mark.parametrize('key', ['', 'root/', '/port1', 'root/tunnel\nname'])
def test_scoped_interface_and_vpn_keys_reject_malformed_identities(field, message, key):
    with pytest.raises(ValueError, match=message):
        parse_conversion_settings({field: [key]})


@pytest.mark.parametrize('field', ['excluded_interfaces', 'existing_vpns'])
def test_scoped_interface_and_vpn_keys_preserve_nested_names_and_long_values(field):
    key = f"{'v' * 20000}/{'tunnel/' + 'n' * 20000}"
    assert parse_conversion_settings({field: [key]})[field] == [key]


@pytest.mark.parametrize('phase', ['ipsec_phase1', 'ipsec_phase2'])
def test_vpn_parameters_accept_nested_names_for_supported_phases(phase):
    key = f'root/{phase}/tunnel/child'
    assert parse_conversion_settings({'vpn_parameters': {key: {'dh_group': 'group14'}}})['vpn_parameters'][key]


@pytest.mark.parametrize('key', [
    '/ipsec_phase1/tunnel', 'root/ipsec_phase3/tunnel',
    'root/ipsec_phase1/', 'root/ipsec_phase2/tunnel\nname',
])
def test_vpn_parameters_reject_malformed_or_unsupported_scopes(key):
    with pytest.raises(ValueError, match='Invalid non-secret VPN parameters'):
        parse_conversion_settings({'vpn_parameters': {key: {}}})


def test_vpn_parameters_accept_long_nested_identity():
    key = f"{'v' * 20000}/ipsec_phase1/{'tunnel/' + 'n' * 20000}"
    assert key in parse_conversion_settings({'vpn_parameters': {key: {}}})['vpn_parameters']


def test_profile_rejection_blocks_interfaces_and_zones_before_rendering():
    plan = planned()
    profile, = plan.management_profiles
    decisions = PANMigrationDecisionSet()
    index = build_plan_dependency_index(plan, decisions)
    classification = {'family': 'management_profile', 'status': 'AMBIGUOUS', 'source_vdom': profile.source_vdom,
        'source_kind': profile.source_kind, 'source_name': profile.source_name, 'target_vsys': None, 'target_name': profile.target_name}
    dispositions, blockers = assess_target_plan(plan, [classification], (), decisions, index)
    assert dispositions[item_key(plan.interfaces[0])].value == 'BLOCK'
    commands = PANSetRenderer().render(plan, dispositions=dispositions, render_blockers=blockers).commands
    assert not any('interface-management-profile' in command for command in commands)
    malformed = replace(plan, management_profiles=(replace(profile, permitted_ips=()),))
    assert not any('interface-management-profile' in command for command in PANSetRenderer().render(malformed).commands)


def test_unknown_group_cannot_be_used_as_a_profile_assignment():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    options = PANMigrationOptions(conversion_settings={'generated_management_profiles': {'other/ping': {'permitted_ips': ['192.0.2.0/24']}}})
    with pytest.raises(ValueError, match='current scoped'):
        FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options)

# --- test_management_profile_reuse.py ---
def _target(extra='', omit=None):
    toggles = ''.join(f'<{name}>{"yes" if name == "ssh" else "no"}</{name}>'
                      for name in MANAGEMENT_PROTOCOLS if name != omit)
    return PaloAltoSourceReporter().analyze_source(f'''<config version="11.1.0"><devices><entry name="dev">
    <network><profiles><interface-management-profile><entry name="reviewed">{toggles}
    <permitted-ip><entry name="192.0.2.0/24"/></permitted-ip>{extra}
    </entry></interface-management-profile></profiles></network></entry></devices></config>''')


def _plan():
    return PANMigrationPlan(management_profiles=(PlannedManagementProfile(source_vdom='root',
        source_kind='management_profile', source_object_type='management_profile', source_name='source',
        target_name='reviewed', protocols=('ssh',), permitted_ips=('192.0.2.0/24',)),))


def test_management_profile_reuse_requires_complete_exact_device_evidence():
    target = _target()
    profile, = target.config.management_profiles
    assert profile.permitted_ips == ['192.0.2.0/24']
    assert classify_target_object_reuse(_plan(), target, 'dev')[0]['status'] == 'EXACT_MATCH'
    assert classify_target_object_reuse(_plan(), _target(omit='http'), 'dev')[0]['status'] == 'AMBIGUOUS'
    assert classify_target_object_reuse(_plan(), _target('<future>yes</future>'), 'dev')[0]['status'] == 'AMBIGUOUS'
    assert classify_target_object_reuse(_plan(), target, 'other')[0]['status'] == 'AMBIGUOUS'
    profile.protocols['http'] = 'yes'
    assert classify_target_object_reuse(_plan(), target, 'dev')[0]['status'] == 'NAME_CONFLICT'


def test_differing_permitted_networks_are_never_reused():
    plan = _plan()
    plan = replace(plan, management_profiles=(replace(plan.management_profiles[0], permitted_ips=('0.0.0.0/0',)),))
    assert classify_target_object_reuse(plan, _target(), 'dev')[0]['status'] == 'NAME_CONFLICT'

# --- test_panos_interface_coverage.py ---
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
