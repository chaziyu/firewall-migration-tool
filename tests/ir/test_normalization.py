from fwmigrate.core.normalizer import IRNormalizer
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy


def anomaly_ir():
    return IRConfig(
        metadata=IRMetadata(hostname="normalization-test", source_vendor="fortigate"),
        policies=[
            IRPolicy(
                name="outbound-threat",
                source=["client"],
                destination=["botnet", "d1", "d2", "d3", "d4"],
                service=["any"],
                action=PolicyAction.DENY,
                migration_status="NORMALIZED",
            )
        ],
    )


def test_normalization_returns_a_change_and_is_idempotent():
    first = IRNormalizer().normalize(anomaly_ir())
    second = IRNormalizer().normalize(first.ir)

    assert first.ir.policies[0].source == ["any"]
    assert "client" in first.ir.policies[0].destination
    assert [change.code for change in first.changes] == [
        "OUTBOUND_THREAT_SOURCE_REWRITE"
    ]
    assert second.changes == []
    assert second.ir == first.ir
