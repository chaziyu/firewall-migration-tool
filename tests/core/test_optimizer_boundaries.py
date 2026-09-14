from fwmigrate.core.normalizer import IRNormalizer
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction


def test_optimizer_does_not_perform_mandatory_normalization():
    ir = IRConfig(
        metadata=IRMetadata(hostname="optimizer-test", source_vendor="fortigate"),
        policies=[
            IRPolicy(
                name="unsafe-anomaly",
                source=["client"],
                destination=["botnet", "d1", "d2", "d3", "d4"],
                service=["any"],
                action=PolicyAction.DENY,
                migration_status="NORMALIZED",
            )
        ],
    )

    RuleOptimizer(ir).find_unused_objects()

    assert ir.policies[0].source == ["client"]
    assert not ir.audit_entries
    assert IRNormalizer().normalize(ir).changes
