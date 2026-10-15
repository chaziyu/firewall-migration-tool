from copy import deepcopy
from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planning.vpn import plan_vpn_crypto
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.vpn_suggestions import build_vpn_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1, FGIPsecPhase2, FGIPsecPolicyPhase1


def source():
    return FGConfig(ipsec_phase1=[FGIPsecPhase1(name='peer', proposal=['aes256-sha256'], dhgrp=[14], keylife=28800)],
        ipsec_phase2=[FGIPsecPhase2(name='traffic', phase1name='peer', proposal=['aes128-sha256'], pfs='enable',
                                 dhgrp=[14], keylifeseconds=3600)])


def plan(config):
    ike, ipsec = plan_vpn_crypto(config, PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    return PANMigrationPlan(ike_crypto_profiles=ike, ipsec_crypto_profiles=ipsec)


def test_crypto_profiles_render_exact_non_secret_pan_os_11_1_paths():
    config = source()
    before = deepcopy(config)
    rendered = PANSetRenderer().render(plan(config))
    assert rendered.commands == (
        'set network ike crypto-profiles ike-crypto-profiles root-peer-ike encryption [ aes-256-cbc ]',
        'set network ike crypto-profiles ike-crypto-profiles root-peer-ike hash [ sha256 ]',
        'set network ike crypto-profiles ike-crypto-profiles root-peer-ike dh-group [ group14 ]',
        'set network ike crypto-profiles ike-crypto-profiles root-peer-ike lifetime seconds 28800',
        'set network ike crypto-profiles ipsec-crypto-profiles root-traffic-ipsec esp encryption [ aes-128-cbc ]',
        'set network ike crypto-profiles ipsec-crypto-profiles root-traffic-ipsec esp authentication [ sha256 ]',
        'set network ike crypto-profiles ipsec-crypto-profiles root-traffic-ipsec dh-group group14',
        'set network ike crypto-profiles ipsec-crypto-profiles root-traffic-ipsec lifetime seconds 3600',
    )
    assert config == before


def test_reviewed_missing_values_sha512_and_day_lifetime_do_not_modify_source():
    config = source()
    config.ipsec_phase2[0].pfs = None
    config.ipsec_phase2[0].keylifeseconds = None
    config.ipsec_phase2[0].proposal = ['aes256-sha512']
    config.ipsec_phase1[0].raw_extra = {'peertype': 'any', 'net-device': 'disable'}
    before = deepcopy(config)
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}, conversion_settings={'vpn_parameters': {
        'root/ipsec_phase2/traffic': {'pfs': 'disable', 'lifetime_seconds': 86400}}})
    ike, ipsec = plan_vpn_crypto(config, options)
    assert ipsec[0].status is PANMigrationStatus.SUPPORTED
    commands = PANSetRenderer().render(PANMigrationPlan(ike_crypto_profiles=ike, ipsec_crypto_profiles=ipsec)).commands
    assert any(command.endswith('lifetime hours 24') for command in commands)
    assert any(command.endswith('authentication [ sha512 ]') for command in commands)
    assert config == before


@pytest.mark.parametrize('change', ['proposal', 'multiple', 'lifetime', 'dh', 'pfs', 'bytes', 'reference', 'policy_namespace', 'vdom', 'unknown'])
def test_crypto_subset_never_fills_defaults_or_crosses_vpn_namespaces(change):
    config = source()
    phase2 = config.ipsec_phase2[0]
    if change == 'proposal':
        phase2.proposal = ['aes256gcm']
    elif change == 'multiple':
        phase2.proposal = ['aes128-sha256', 'aes256-sha256']
    elif change == 'lifetime':
        phase2.keylifeseconds = None
    elif change == 'dh':
        phase2.dhgrp = []
    elif change == 'pfs':
        phase2.pfs = None
    elif change == 'bytes':
        phase2.keylifekbs = 1000
    elif change == 'reference':
        phase2.phase1name = 'missing'
    elif change == 'policy_namespace':
        config.ipsec_policy_phase1 = [FGIPsecPolicyPhase1(**config.ipsec_phase1.pop().model_dump())]
    elif change == 'vdom':
        config.ipsec_phase1[0].vdom = 'branch'
    else:
        phase2.raw_extra['unknown'] = 'preserved'
    result = plan(config)
    assert result.ipsec_crypto_profiles[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert not any('ipsec-crypto-profiles' in command for command in PANSetRenderer().render(result).commands)


def test_disabled_pfs_is_explicit_and_profile_names_are_device_scoped():
    config = source()
    config.ipsec_phase2[0].pfs = 'disable'
    config.ipsec_phase2[0].dhgrp = []
    result = plan(config)
    assert 'set network ike crypto-profiles ipsec-crypto-profiles root-traffic-ipsec dh-group no-pfs' in PANSetRenderer().render(result).commands
    first = result.ike_crypto_profiles[0]
    collision = replace(first, source_vdom='branch', target_vsys='vsys2')
    assert not PANSetRenderer().render(PANMigrationPlan(ike_crypto_profiles=(first, collision))).commands


@pytest.mark.parametrize('field,value', [('encryption', 'unknown'), ('dh_group', None), ('lifetime_seconds', 179),
    ('target_name', 'x' * 32), ('target_vsys', None)])
def test_invalid_crypto_models_cannot_bypass_renderer_validation(field, value):
    first = replace(plan(source()).ike_crypto_profiles[0], **{field: value})
    assert not PANSetRenderer().render(PANMigrationPlan(ike_crypto_profiles=(first,))).commands


def test_recommendations_block_authentication_and_reject_cross_namespace_phase1():
    config = source()
    config.ipsec_policy_phase1 = [FGIPsecPolicyPhase1(**config.ipsec_phase1.pop().model_dump())]
    recommendations = build_vpn_recommendations(config, object(), PANMigrationDecisionSet())
    assert any('Authentication material' in reason for row in recommendations for reason in row.blockers)
    assert any('Phase 1 gateway is missing' in reason for row in recommendations if row.source_kind == 'ipsec_phase2' for reason in row.blockers)
def test_version_verified_phase2_values_are_separate_from_source_and_block_conflicting_overrides():
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.vpn import vpn_parameter_requirements, validate_vpn_parameters
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
    source = '''config vpn ipsec phase1-interface
edit site
set interface port1
next
end
config vpn ipsec phase2-interface
edit selectors
set phase1name site
set proposal aes256-sha256
set dhgrp 14
next
end
'''
    header = '#config-version=FG100E-7.2.13-FW-build1762-260128\n'
    analysis = FortiGateSourceReporter().analyze_source(header + source)
    explicit = analysis.extracted.config.model_dump()
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}})
    _, profiles = plan_vpn_crypto(analysis.extracted.config, options, analysis.derived)
    assert profiles[0].status is PANMigrationStatus.SUPPORTED
    assert profiles[0].dh_group == 'group14' and profiles[0].lifetime_seconds == 43200
    assert not any(group['source_kind'] == 'ipsec_phase2' for group in vpn_parameter_requirements(analysis.extracted.config, analysis.derived))
    assert analysis.extracted.config.model_dump() == explicit
    assert analysis.extracted.config.ipsec_phase2[0].pfs is None
    with pytest.raises(ValueError, match='verified effective'):
        validate_vpn_parameters(analysis.extracted.config,
            {'vpn_parameters': {'root/ipsec_phase2/selectors': {'pfs': 'disable'}}}, analysis.derived)
    unknown = FortiGateSourceReporter().analyze_source(source)
    _, blocked = plan_vpn_crypto(unknown.extracted.config, options, unknown.derived)
    assert blocked[0].status is not PANMigrationStatus.SUPPORTED
    disabled = FortiGateSourceReporter().analyze_source(header + source.replace('set dhgrp 14', 'set pfs disable'))
    _, profile = plan_vpn_crypto(disabled.extracted.config, options, disabled.derived)
    assert profile[0].status is PANMigrationStatus.SUPPORTED and profile[0].dh_group == 'no-pfs'
