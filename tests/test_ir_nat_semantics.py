from fwmigrate.ir.core import (
    IRNATAddressRangeMapping,
    IRNATPortRange,
    IRNATRule,
    IRNATRuntimeBehavior,
)
from fwmigrate.ir.enums import NATFamily, NATSourcePortBehavior, NATType
from fwmigrate.ir.io import load_ir_payload


def test_nat_ir_represents_translation_fidelity_without_source_attributes():
    rule = IRNATRule(
        name="sctp-range",
        type=NATType.ADDRESS_TRANSLATION,
        nat_family=NATFamily.NAT44,
        original_address_family="ipv4",
        translated_address_family="ipv4",
        protocol_number=132,
        protocol_name="SCTP",
        original_source_ports=[IRNATPortRange(start=1000, end=2000)],
        address_range_mappings=[IRNATAddressRangeMapping(
            original_start="10.0.0.1",
            original_end="10.0.0.4",
            translated_start="192.0.2.1",
            translated_end="192.0.2.4",
        )],
        source_port_behavior=NATSourcePortBehavior.PRESERVE_STRICT,
        runtime_behavior=IRNATRuntimeBehavior(fixed_port=True),
        source_origin="ip-translation",
        source=["10.0.0.0/24"],
        destination=["any"],
        services=["sctp"],
    )

    assert rule.safe_for_target_generation
    assert rule.model_dump(mode="json")["nat_family"] == "nat44"


def test_schema_1_34_nat_migration_adds_new_defaults():
    ir = load_ir_payload({
        "schema_version": "1.34",
        "metadata": {"source_vendor": "fortigate"},
        "nat_rules": [{"name": "legacy", "type": "central"}],
    })

    assert ir.schema_version == "1.48"
    assert ir.nat_rules[0].address_range_mappings == []
    assert ir.nat_rules[0].source_origin is None
