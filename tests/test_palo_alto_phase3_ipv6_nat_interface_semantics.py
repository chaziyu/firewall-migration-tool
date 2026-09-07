from fwmigrate.ir.enums import NATFamily, NATTranslationMode
from fwmigrate.parsers.palo_alto import PANOSSourceParser


def _extract(rule_xml: str):
    xml = f"""
    <config version="12.1.0">
      <devices><entry name="localhost.localdomain">
        <network><interface><ethernet>
          <entry name="ethernet1/1"><layer3>
            <ip><entry name="203.0.113.1/24"/></ip>
            <ipv6><address><entry name="2001:db8:ffff::1/64"/></address></ipv6>
          </layer3></entry>
        </ethernet></interface></network>
        <vsys><entry name="vsys1">
          <rulebase><nat><rules>{rule_xml}</rules></nat></rulebase>
        </entry></vsys>
      </entry></devices>
    </config>
    """
    return PANOSSourceParser().extract(xml)


def test_nat64_interface_address_uses_phase2_family_evidence():
    result = _extract("""
      <entry name="nat64-ifaddr">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>2001:db8:1::/64</member></source>
        <destination><member>64:ff9b::/96</member></destination>
        <service>any</service><nat-type>nat64</nat-type>
        <source-translation><dynamic-ip-and-port><interface-address>
          <interface>ethernet1/1</interface><ip>203.0.113.1/24</ip>
        </interface-address></dynamic-ip-and-port></source-translation>
      </entry>
    """)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert rule.nat_family == NATFamily.NAT64
    assert rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert semantics["flow"] == "ipv6-initiated"
    assert semantics["interface_address_families"] == ["ipv4"]
    assert rule.original_address_family == "ipv6"
    assert rule.translated_address_family == "ipv4"
    assert "nat64-interface-address-family-indeterminate" not in rule.review_reasons


def test_nptv6_dynamic_interface_ipv4_selector_is_flagged():
    result = _extract("""
      <entry name="npt-bad-ifaddr">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>2001:db8:1::/64</member></source>
        <destination><member>2001:db8:2::/64</member></destination>
        <service>any</service><nat-type>nptv6</nat-type>
        <source-translation><dynamic-ip><interface-address>
          <interface>ethernet1/1</interface><ip>203.0.113.1/24</ip>
        </interface-address></dynamic-ip></source-translation>
      </entry>
    """)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert semantics["dynamic_interface_prefix"] is True
    assert semantics["interface_address_families"] == ["ipv4"]
    assert "nptv6-interface-prefix-must-be-ipv6" in rule.review_reasons
    assert rule.source_attributes["pan_ipv6_nat_semantics_complete"] is False
