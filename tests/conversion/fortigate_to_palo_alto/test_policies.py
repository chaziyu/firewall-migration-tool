from dataclasses import replace
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from types import SimpleNamespace
from fwmigrate.conversion.fortigate_to_palo_alto import run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_object_reuse import classify_target_object_reuse
from fwmigrate.vendors.palo_alto.model.policy import PANSecurityRule
from fwmigrate.vendors.palo_alto.source_model import PANScope
import io
import json
from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage

# --- test_policy_identities.py ---
SOURCE = '''config system interface
edit inside
set type physical
next
edit outside
set type physical
next
end
config firewall policy
edit 1
set name staff-out
set srcintf inside
set dstintf outside
set srcaddr all
set dstaddr all
set action accept
set schedule always
set service ALL
set groups staff
next
end
'''


def options(settings):
    return PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
        interfaces={'root': {'inside': {'target_interface': 'ethernet1/1', 'target_zone': 'inside'},
            'outside': {'target_interface': 'ethernet1/2', 'target_zone': 'outside'}}}, conversion_settings=settings)


def test_identity_mapping_needs_reviewed_authentication_and_never_applies_to_nat():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    settings = {'identity_mappings': {'root': {'group/staff': 'CORP/staff'}}}
    planner = FortiGateToPaloAltoPlanner()
    blocked = planner.plan(analysis.extracted.config, analysis.derived, options(settings), include_configuration=True)
    assert blocked.security_rules[0].status is not PANMigrationStatus.SUPPORTED
    assert not any('rulebase security' in command for command in PANSetRenderer().render(blocked).commands)
    settings['identity_prerequisites'] = ['root']
    plan = planner.plan(analysis.extracted.config, analysis.derived, options(settings), include_configuration=True)
    assert plan.security_rules[0].status is PANMigrationStatus.SUPPORTED
    assert 'set vsys vsys1 rulebase security rules staff-out source-user [ CORP/staff ]' in PANSetRenderer().render(plan).commands
    analysis = FortiGateSourceReporter().analyze_source(SOURCE.replace('set groups staff', 'set groups staff\nset nat enable'))
    nat = planner.plan(analysis.extracted.config, analysis.derived, options(settings), include_configuration=True)
    assert all(rule.status is not PANMigrationStatus.SUPPORTED for rule in nat.nat_rules)
    forged = replace(plan, security_rules=(replace(plan.security_rules[0], source_users=('any',)),))
    assert not any('rulebase security' in command for command in PANSetRenderer().render(forged).commands)


@pytest.mark.parametrize('name', ['any', 'known-user', 'unknown', '', 'unsafe\nidentity'])
def test_identity_mapping_rejects_wildcards_and_invalid_target_names(name):
    with pytest.raises(ValueError):
        options({'identity_mappings': {'root': {'group/staff': name}}})


def test_identity_names_are_scoped_and_unknown_source_mappings_fail():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    with pytest.raises(ValueError, match='current source identities'):
        FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived,
            options({'identity_mappings': {'other': {'group/staff': 'CORP/staff'}}}))

# --- test_policy_logging.py ---
_LOGGING_SOURCE = '''config system interface
 edit lan
  set type physical
  set ip 192.0.2.1 255.255.255.0
 next
 edit wan
  set type physical
  set ip 198.51.100.1 255.255.255.0
 next
end
config system zone
 edit trust
  set interface lan
 next
 edit untrust
  set interface wan
 next
end
config firewall policy
 edit 1
  set name traffic
  set srcintf lan
  set dstintf wan
  set srcaddr all
  set dstaddr all
  set service ALL
  set schedule always
  set action accept
  {logging}
 next
end
'''

MAPPING = {'vdoms': {'root': {'vsys': 'vsys1', 'virtual_router': 'vr-root'}},
           'zones': {'root': {'trust': {'target_zone': 'trust'}, 'untrust': {'target_zone': 'untrust'}}},
           'interfaces': {'root': {
               'lan': {'target_interface': 'ethernet1/1', 'target_zone': 'trust'},
               'wan': {'target_interface': 'ethernet1/2', 'target_zone': 'untrust'}}}}


@pytest.mark.parametrize('logging,start,end,ready', [
    ('', None, None, True), ('set logtraffic all', None, 'yes', True),
    ('set logtraffic disable', 'no', 'no', True), ('set logtraffic utm', None, None, False),
    ('set logtraffic unknown', None, None, False),
    ('set logtraffic all\n  set logtraffic-start enable', None, 'yes', False),
])
def test_source_logging_reaches_plan_commands_and_artifact_status(logging, start, end, ready):
    analysis = FortiGateSourceReporter().analyze_source(_LOGGING_SOURCE.format(logging=logging))
    original = analysis.extracted.config.model_copy(deep=True)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
                                    options=PANMigrationOptions(**MAPPING))
    rule = result.plan.security_rules[0]
    assert (rule.log_start, rule.log_end) == (start, end)
    assert (result.artifact_status == 'READY') == ready
    logs = [command for command in result.rendered.commands if ' log-' in command]
    assert logs == ([f'set vsys vsys1 rulebase security rules traffic log-start {start}'] if start and ready else []) + (
        [f'set vsys vsys1 rulebase security rules traffic log-end {end}'] if end and ready else [])
    assert analysis.extracted.config == original
    if not ready:
        assert rule.warnings
        assert not any('rulebase security rules traffic' in command for command in result.rendered.commands)


def test_different_explicit_target_logging_is_a_conflict_and_never_reused():
    analysis = FortiGateSourceReporter().analyze_source(_LOGGING_SOURCE.format(logging='set logtraffic all'))
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived, options=PANMigrationOptions(**MAPPING))
    rule = replace(result.plan.security_rules[0], target_name='traffic')
    existing = PANSecurityRule(name='traffic', source_path='/rulebase/security/rules',
        scope=PANScope(kind='vsys', name='vsys1', vsys='vsys1', device_name='fw'),
        from_zones=['trust'], to_zones=['untrust'], source=['any'], destination=['any'],
        service=['any'], action='allow', log_end='no',
        explicit_fields={'from_zones', 'to_zones', 'source', 'destination', 'service', 'action', 'log_end'})
    target = SimpleNamespace(config=SimpleNamespace(security_rules=[existing]))
    rows = classify_target_object_reuse(PANMigrationPlan(security_rules=(rule,)), target, 'fw')
    assert rows[0]['status'] == 'NAME_CONFLICT'

# --- test_session_helper_review_labels.py ---
_SESSION_HELPER_SOURCE = '''config system session-helper
edit 1
set name sip
set port 5060
set protocol 17
set password synthetic-secret-value
next
edit 2
set name sip
set port 5061
set protocol 6
next
end
'''


def test_native_ids_and_searchable_helper_types_are_both_preserved():
    source = FortiGateSourceReporter().analyze_source(_SESSION_HELPER_SOURCE).extracted.config
    original = source.model_dump()
    rows = build_migration_coverage(source)['unplanned']
    assert {row['source_name'] for row in rows} == {'1', '2'}
    assert all('sip' in row['reason'] and 'system session-helper' in row['reason'] for row in rows)
    assert all(row['source_vdom'] == 'root' and row['readiness'] == 'UNSUPPORTED' for row in rows)
    assert 'synthetic-secret-value' not in json.dumps(rows)
    assert source.model_dump() == original


def test_missing_helper_type_is_not_filled_with_an_assumed_type():
    source = FortiGateSourceReporter().analyze_source('config system session-helper\nedit 1\nset port 5060\nnext\nend\n').extracted.config
    row, = build_migration_coverage(source)['unplanned']
    assert row['source_name'] == '1'
    assert 'sip' not in row['reason'] and 'None' not in row['reason']


def test_labels_preserve_native_id_collisions_across_source_scopes():
    text = 'config global\n' + _SESSION_HELPER_SOURCE + 'end\nconfig vdom\nedit blue\n' + _SESSION_HELPER_SOURCE + 'next\nend\n'
    source = FortiGateSourceReporter().analyze_source(text).extracted.config
    rows = build_migration_coverage(source)['unplanned']
    assert {(row['source_vdom'], row['source_name']) for row in rows} == {(None, '1'), (None, '2'), ('blue', '1'), ('blue', '2')}
    assert all('sip' in row['reason'] for row in rows)


def test_browser_review_tasks_include_helper_type_without_changing_identity():
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    preview = client.post('/api/preview', data={'file': (io.BytesIO(_SESSION_HELPER_SOURCE.encode()), 'source.conf')})
    assert preview.status_code == 200
    response = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert response.status_code == 200
    draft = response.get_json()['draft']
    rows = [row for row in draft['configuration'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in rows} == {'1', '2'}
    assert all('sip' in ' '.join(row['blocking_reasons']) and row['status'] == 'UNSUPPORTED' for row in rows)
    tasks = [row for row in draft['issues'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in tasks} == {'1', '2'}
    assert all('sip' in row['explanation'] for row in tasks)
    assert 'synthetic-secret-value' not in json.dumps(draft)
