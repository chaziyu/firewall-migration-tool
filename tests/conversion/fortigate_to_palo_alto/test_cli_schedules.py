from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedSchedule, PlannedSecurityRule,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner, PANMigrationOptions
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from dataclasses import replace
import pytest


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
