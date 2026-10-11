from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedSchedule, PlannedSecurityRule, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer


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
        PlannedSecurityRule(source_object_type="security_rule", source_name="allow-web", target_vsys="vsys1",
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
        "set vsys vsys1 rulebase security rules allow-web schedule work",
        "set vsys vsys1 rulebase security rules allow-web negate-source yes",
        "set vsys vsys1 rulebase security rules allow-web negate-destination yes",
        "set vsys vsys1 rulebase security rules allow-web disabled yes",
        'set vsys vsys1 rulebase security rules allow-web description "web access"',
        "set vsys vsys1 rulebase security rules allow-web action allow",
    )
