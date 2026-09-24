from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_icmp_unreachable_is_extracted_for_ordinary_security_rules():
    config = build_panos_config("""<config><shared><rulebase><security><rules><entry name='allow-web'>
      <action>allow</action><icmp-unreachable>yes</icmp-unreachable>
    </entry></rules></security></rulebase></shared></config>""")
    rule, = config.security_rules
    assert rule.icmp_unreachable == "yes"
    assert "icmp_unreachable" in rule.explicit_fields
