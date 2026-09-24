from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_security_rule_order_is_retained_per_source_rulebase():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "policies.xml"
    rules = build_panos_config(path.read_text()).security_rules
    assert [rule.name for rule in rules[:5]] == ["Pre-First", "Same-Name", "Allow-Basic", "Deny-Basic", "Drop-Rule"]
