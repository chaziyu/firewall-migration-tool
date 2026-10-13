from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedNATRule,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer


def test_snat_pool_interface_address_and_dnat_commands():
    plan = PANMigrationPlan(nat_rules=(
        PlannedNATRule(source_object_type="nat_rule", source_name="snat-pool", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("untrust",),
                       source_addresses=("clients",), destination_addresses=("any",), service="https",
                       to_interface="ethernet1/2", source_translation_type="dynamic-ip-and-port",
                       translated_addresses=("203.0.113.10", "203.0.113.11")),
        PlannedNATRule(source_object_type="nat_rule", source_name="snat-interface", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("untrust",),
                       source_interface_address=True, source_translation_type="dynamic-ip-and-port", to_interface="ethernet1/2"),
        PlannedNATRule(source_object_type="nat_rule", source_name="dnat", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, from_zones=("untrust",), to_zones=("trust",),
                       source_addresses=("any",), destination_addresses=("198.51.100.10",), service="https",
                       to_interface="ethernet1/1", destination_translated_address="10.0.0.10",
                       destination_translated_port="8443"),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 rulebase nat rules snat-pool nat-type ipv4",
        "set vsys vsys1 rulebase nat rules snat-pool from [ trust ]",
        "set vsys vsys1 rulebase nat rules snat-pool to [ untrust ]",
        "set vsys vsys1 rulebase nat rules snat-pool source [ clients ]",
        "set vsys vsys1 rulebase nat rules snat-pool destination [ any ]",
        "set vsys vsys1 rulebase nat rules snat-pool service https",
        "set vsys vsys1 rulebase nat rules snat-pool to-interface ethernet1/2",
        "set vsys vsys1 rulebase nat rules snat-pool source-translation dynamic-ip-and-port translated-address [ 203.0.113.10 203.0.113.11 ]",
        "set vsys vsys1 rulebase nat rules snat-interface nat-type ipv4",
        "set vsys vsys1 rulebase nat rules snat-interface from [ trust ]",
        "set vsys vsys1 rulebase nat rules snat-interface to [ untrust ]",
        "set vsys vsys1 rulebase nat rules snat-interface to-interface ethernet1/2",
        "set vsys vsys1 rulebase nat rules snat-interface source-translation dynamic-ip-and-port interface-address interface ethernet1/2",
        "set vsys vsys1 rulebase nat rules dnat nat-type ipv4",
        "set vsys vsys1 rulebase nat rules dnat from [ untrust ]",
        "set vsys vsys1 rulebase nat rules dnat to [ trust ]",
        "set vsys vsys1 rulebase nat rules dnat source [ any ]",
        "set vsys vsys1 rulebase nat rules dnat destination [ 198.51.100.10 ]",
        "set vsys vsys1 rulebase nat rules dnat service https",
        "set vsys vsys1 rulebase nat rules dnat to-interface ethernet1/1",
        "set vsys vsys1 rulebase nat rules dnat destination-translation translated-address 10.0.0.10",
        "set vsys vsys1 rulebase nat rules dnat destination-translation translated-port 8443",
    )


def test_interface_address_nat_requires_an_explicit_interface():
    item = PlannedNATRule(source_object_type="nat_rule", source_name="incomplete", target_vsys="vsys1",
                          status=PANMigrationStatus.SUPPORTED, from_zones=("any",), to_zones=("any",),
                          source_interface_address=True, source_translation_type="dynamic-ip-and-port")
    rendered = PANSetRenderer().render(PANMigrationPlan(nat_rules=(item,)))
    assert rendered.commands == ()
    assert "missing_nat_interface" in rendered.report["items"][0]["render_blockers"]
