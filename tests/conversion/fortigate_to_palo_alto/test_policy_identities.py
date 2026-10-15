from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


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
