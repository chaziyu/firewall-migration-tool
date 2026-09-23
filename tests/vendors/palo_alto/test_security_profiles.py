from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_security_profile_source_is_kept_with_policy_models():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "policies.xml"
    config = build_panos_config(path.read_text())
    assert config.security_rules
    assert any(rule.profile_setting is not None for rule in config.security_rules)
