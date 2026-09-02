from fwmigrate.generators.nat_capabilities import nat_capabilities
from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATFamily, NATType


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
