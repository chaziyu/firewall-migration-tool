from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedSchedule, PlannedSecurityRule, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
import pytest


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
