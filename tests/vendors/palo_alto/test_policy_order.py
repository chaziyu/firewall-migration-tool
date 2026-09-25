from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_security_rule_order_is_retained_per_source_rulebase():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "policies.xml"
    rules = build_panos_config(path.read_text()).security_rules
    assert [rule.name for rule in rules[:5]] == ["Pre-First", "Same-Name", "Allow-Basic", "Deny-Basic", "Drop-Rule"]


def test_nat_rule_source_order_is_preserved():
    config = build_panos_config("""<config><shared><rulebase><nat><rules>
      <entry name='nat-first'/><entry name='nat-second'/>
    </rules></nat></rulebase></shared></config>""")
    assert [rule.name for rule in config.nat_rules] == ["nat-first", "nat-second"]


def test_sdwan_rule_source_order_is_preserved():
    config = build_panos_config("""<config><shared><network><sdwan><rules>
      <entry name='sdwan-first'/><entry name='sdwan-second'/>
    </rules></sdwan></network></shared></config>""")
    assert [rule.name for rule in config.sdwan_rules] == ["sdwan-first", "sdwan-second"]
