from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedSecurityRule, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer


def test_security_rule_match_flags_and_actions():
    plan = PANMigrationPlan(
        zones=(
            PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED),
            PlannedZone(source_object_type="zone", source_name="untrust", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED),
        ),
        security_rules=(
        PlannedSecurityRule(source_object_type="security_rule", source_name="allow-web", target_vsys="vsys1",
                            status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("untrust",),
                            sources=("any",), destinations=("any",), services=("any",), schedule="work",
                            negate_source=True, negate_destination=True, disabled=True,
                            description="web access", action="allow"),
        ),
    )

    assert PANSetRenderer().render(plan).commands == (
        "set system setting target-vsys vsys1",
        "set rulebase security rules allow-web from [ trust ]",
        "set rulebase security rules allow-web to [ untrust ]",
        "set rulebase security rules allow-web source [ any ]",
        "set rulebase security rules allow-web destination [ any ]",
        "set rulebase security rules allow-web service [ any ]",
        "set rulebase security rules allow-web schedule work",
        "set rulebase security rules allow-web negate-source yes",
        "set rulebase security rules allow-web negate-destination yes",
        "set rulebase security rules allow-web disabled yes",
        'set rulebase security rules allow-web description "web access"',
        "set rulebase security rules allow-web action allow",
    )
