from fwmigrate.core.normalizer import RuleNormalizer
from fwmigrate.ir.core import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction


def test_normalizer_preserves_existing_anomaly_correction():
    policy = IRPolicy(
        name="Bad-IP-NTT",
        source=["bad-host"],
        destination=["botnet-feed", "dst-2", "dst-3", "dst-4", "dst-5"],
        service=["HTTPS"],
        action=PolicyAction.DENY,
    )
    ir = IRConfig(
        metadata=IRMetadata(source_vendor="source"),
        policies=[policy],
    )

    RuleNormalizer(ir).normalize_outbound_threat_source_anomalies()

    assert policy.source == ["any"]
    assert "bad-host" in policy.destination
    assert ir.audit_entries[0].category == "Policy Optimization"
