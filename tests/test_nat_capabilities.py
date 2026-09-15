from fwmigrate.generators.nat_capabilities import (
    checkpoint_fortigate_central_snat_reason,
    nat_capabilities,
    plan_fortigate_central_snat,
)
from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATFamily, NATTranslationMode, NATType


def test_target_capability_gate_withholds_unsupported_normalized_nat():
    rule = IRNATRule(
        name="central",
        type=NATType.CENTRAL,
        source_policy_reference="1",
        source=["src"],
        destination=["dst"],
        services=["any"],
        nat_family=NATFamily.NAT44,
    )

    assert rule.migration_status == "NORMALIZED"
    assert nat_capabilities("palo_alto").unsupported_reason(rule) == "central NAT"


def test_target_capability_gate_withholds_persistent_dipp():
    rule = IRNATRule(
        name="persistent",
        type=NATType.SOURCE,
        source_translation_mode=NATTranslationMode.PERSISTENT_DYNAMIC_IP_AND_PORT,
    )

    assert nat_capabilities("palo_alto").unsupported_reason(rule) == (
        "persistent dynamic IP-and-port NAT"
    )


def test_target_capability_gate_withholds_static_nat():
    rule = IRNATRule(
        name="static",
        type=NATType.STATIC,
        source_policy_reference="1",
        source=["any"],
        destination=["198.51.100.10/32"],
        services=["any"],
        translated_destinations=["10.0.0.10/32"],
        source_translation_bidirectional=True,
    )

    assert rule.safe_for_target_generation is False
    assert nat_capabilities("fortigate").unsupported_reason(rule) == "static NAT"
    assert nat_capabilities("palo_alto").unsupported_reason(rule) == "static NAT"


def test_checkpoint_automatic_snat_requires_explicit_equivalence_evidence():
    rule = IRNATRule(
        name="automatic-hide", type=NATType.SOURCE,
        source_policy_reference="7", source=["LAN"], destination=["all"], services=["ALL"],
        source_translation_mode=NATTranslationMode.INTERFACE_ADDRESS,
        source_to_interfaces=["wan1"], source_origin="automatic",
        source_attributes={"checkpoint-nat-origin": "automatic"},
    )

    assert checkpoint_fortigate_central_snat_reason(rule) == (
        "checkpoint-automatic-nat-equivalence-not-proven"
    )
    assert plan_fortigate_central_snat(rule) is None


def test_checkpoint_management_ip_pool_name_match_is_not_promoted_to_generic_snat_pool():
    rule = IRNATRule(
        name="manual-hide-with-management-pool-name",
        type=NATType.SOURCE,
        source_policy_reference="8",
        source=["LAN"],
        destination=["all"],
        services=["ALL"],
        translated_sources=["CP-IP-Pool"],
        source_translation_mode=NATTranslationMode.DYNAMIC_IP_AND_PORT,
        source_attributes={
            "checkpoint-source-nat-method-resolution": {
                "resolved": True,
                "mode": "dynamic-ip-and-port",
                "method": "hide",
                "evidence": ["rule:method=hide"],
                "reasons": [],
            },
        },
    )

    assert checkpoint_fortigate_central_snat_reason(rule, {"CP-IP-Pool"}) == (
        "checkpoint-management-ip-pool-not-generic-snat"
    )
    assert plan_fortigate_central_snat(rule, {"CP-IP-Pool"}) is None


def test_checkpoint_explicit_source_pool_reference_remains_convertible():
    rule = IRNATRule(
        name="manual-hide-with-explicit-pool",
        type=NATType.SOURCE,
        source_policy_reference="9",
        source=["LAN"],
        destination=["all"],
        services=["ALL"],
        translated_sources=["PortablePool"],
        source_pool_references=["PortablePool"],
        source_translation_mode=NATTranslationMode.DYNAMIC_IP_AND_PORT,
        source_attributes={
            "checkpoint-source-nat-method-resolution": {
                "resolved": True,
                "mode": "dynamic-ip-and-port",
                "method": "hide",
                "evidence": ["rule:method=hide"],
                "reasons": [],
            },
        },
    )

    assert checkpoint_fortigate_central_snat_reason(rule, {"PortablePool"}) is None
    planned = plan_fortigate_central_snat(rule, {"PortablePool"})
    assert planned is not None
    assert planned.type == NATType.CENTRAL
    assert planned.source_pool_references == ["PortablePool"]
