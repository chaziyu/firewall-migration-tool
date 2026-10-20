from dataclasses import replace

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PlannedManagementProfile
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_object_reuse import classify_target_object_reuse
from fwmigrate.vendors.palo_alto.model.management_profile import MANAGEMENT_PROTOCOLS
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


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
