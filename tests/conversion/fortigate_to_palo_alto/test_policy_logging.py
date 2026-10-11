from dataclasses import replace
from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_object_reuse import classify_target_object_reuse
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.palo_alto.model.policy import PANSecurityRule
from fwmigrate.vendors.palo_alto.source_model import PANScope


SOURCE = '''config system interface
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
    analysis = FortiGateSourceReporter().analyze_source(SOURCE.format(logging=logging))
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
    analysis = FortiGateSourceReporter().analyze_source(SOURCE.format(logging='set logtraffic all'))
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
