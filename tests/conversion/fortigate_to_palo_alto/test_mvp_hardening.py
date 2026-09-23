from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedNATRule,
    PlannedSecurityRule, PlannedService, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan


def test_structured_plan_renders_scoped_policy_and_nat_commands_in_order():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_object_type="address", source_name="web", target_vsys="vsys1",
                                   target_name="web", status=PANMigrationStatus.SUPPORTED,
                                   address_type="ip-netmask", value="10.0.0.5/32"),),
        services=(PlannedService(source_object_type="service", source_name="web-svc", target_vsys="vsys1",
                                  target_name="web-svc", status=PANMigrationStatus.SUPPORTED,
                                  protocol="tcp", destination_port="443"),),
        zones=(PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1", target_name="trust",
                           status=PANMigrationStatus.SUPPORTED),
               PlannedZone(source_object_type="zone", source_name="untrust", target_vsys="vsys1", target_name="untrust",
                           status=PANMigrationStatus.SUPPORTED)),
        security_rules=(PlannedSecurityRule(source_object_type="security_rule", source_name="allow-web",
            target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
            from_zones=("trust",), to_zones=("untrust",), sources=("web",), destinations=("any",),
            services=("web-svc",), action="allow", negate_source=True, description="web access"),),
        nat_rules=(PlannedNATRule(source_object_type="nat_rule", source_name="snat", target_vsys="vsys1",
            target_name="snat", status=PANMigrationStatus.SUPPORTED, from_zones=("trust",),
            to_zones=("untrust",), source_translation_type="dynamic-ip-and-port",
            translated_addresses=("203.0.113.5",)),),
    )
    validation = validate_plan(plan)
    commands = PANSetRenderer().render(plan, validation).commands
    assert commands[0] == "set vsys vsys1 address web ip-netmask 10.0.0.5/32"
    assert "set vsys vsys1 rulebase nat rules snat source-translation dynamic-ip-and-port translated-address 203.0.113.5" in commands
    assert "set vsys vsys1 rulebase security rules allow-web action allow" in commands


def test_validation_blocks_manual_review_from_rendered_artifact(tmp_path):
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_name="review", status=PANMigrationStatus.MANUAL_REVIEW),))
    rendered = PANSetRenderer().render_files(plan, tmp_path)
    assert rendered.commands == ()
