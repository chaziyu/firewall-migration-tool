from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.target.profile import parse_conversion_settings
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import assess_target_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


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
