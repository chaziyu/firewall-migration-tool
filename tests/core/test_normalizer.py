from fwmigrate.core.normalizer import RuleNormalizer


def test_normalizer_exposes_outbound_threat_source_normalization():
    assert hasattr(RuleNormalizer, "normalize_outbound_threat_source_anomalies")
