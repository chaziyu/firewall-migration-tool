from fwmigrate.ir.enums import NATTranslationMode
from fwmigrate.parsers.palo_alto import PANOSSourceParser


def _extract(rule_xml: str, *, panorama: bool = False):
    if panorama:
        xml = f"""
        <config version="12.1.0">
          <device-group>
            <entry name="DG1">
              <pre-rulebase><nat><rules>{rule_xml}</rules></nat></pre-rulebase>
            </entry>
          </device-group>
        </config>
        """
    else:
        xml = f"""
        <config version="12.1.0">
          <devices>
            <entry name="localhost.localdomain">
              <network>
                <interface><ethernet>
                  <entry name="ethernet1/1">
                    <layer3>
                      <ip><entry name="203.0.113.1/24"/></ip>
                      <ipv6><address><entry name="2001:db8::1/64"/></address></ipv6>
                    </layer3>
                  </entry>
                </ethernet></interface>
              </network>
              <vsys><entry name="vsys1">
                <address>
                  <entry name="pool1"><ip-netmask>203.0.113.10/32</ip-netmask></entry>
                </address>
                <rulebase><nat><rules>{rule_xml}</rules></nat></rulebase>
              </entry></vsys>
            </entry>
          </devices>
        </config>
        """
    return PANOSSourceParser().extract(xml)


def _base_rule(name: str, translation: str) -> str:
    return f"""
    <entry name="{name}">
      <from><member>trust</member></from>
      <to><member>untrust</member></to>
      <source><member>any</member></source>
      <destination><member>any</member></destination>
      <service>any</service>
      {translation}
    </entry>
    """


def test_primary_interface_address_preserves_ipv4_ipv6_floating_and_resolution():
    rule_xml = _base_rule(
        "all-interface-fields",
        """
        <source-translation><dynamic-ip-and-port><interface-address>
          <interface>ethernet1/1</interface>
          <ip>203.0.113.1/24</ip>
          <ipv6>2001:db8::1/64</ipv6>
          <floating-ip>198.51.100.5</floating-ip>
        </interface-address></dynamic-ip-and-port></source-translation>
        """,
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    details = rule.source_attributes["pan_interface_address_details"]

    assert rule.source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT
    assert details["interface"] == "ethernet1/1"
    assert details["resolved_interface"] == "ethernet1/1"
    assert details["resolution"] == "resolved"
    assert details["ip"] == ["203.0.113.1/24"]
    assert details["ipv4_addresses"] == ["203.0.113.1/24"]
    assert details["ipv6_addresses"] == ["2001:db8::1/64"]
    assert details["floating_ips"] == ["198.51.100.5"]
    assert details["value_validation"]["ipv4_addresses"][0]["valid"] is True
    assert details["value_validation"]["ipv6_addresses"][0]["valid"] is True
    assert details["value_validation"]["floating_ips"][0]["valid"] is True
    assert "interface-address-semantics" not in rule.review_reasons


def test_interface_address_preserves_repeated_source_values_without_collapse():
    rule_xml = _base_rule(
        "repeated-values",
        """
        <source-translation><dynamic-ip-and-port><interface-address>
          <interface>ethernet1/1</interface>
          <ip><member>203.0.113.1/24</member><member>203.0.113.2/24</member></ip>
          <ipv6><member>2001:db8::1/64</member><member>2001:db8::2/64</member></ipv6>
          <floating-ip><member>198.51.100.5</member><member>198.51.100.6</member></floating-ip>
        </interface-address></dynamic-ip-and-port></source-translation>
        """,
    )
    result = _extract(rule_xml)
    details = result.canonical_ir.nat_rules[0].source_attributes[
        "pan_interface_address_details"
    ]

    assert details["ipv4_addresses"] == ["203.0.113.1/24", "203.0.113.2/24"]
    assert details["ipv6_addresses"] == ["2001:db8::1/64", "2001:db8::2/64"]
    assert details["floating_ips"] == ["198.51.100.5", "198.51.100.6"]


def test_dynamic_ip_fallback_interface_address_is_structured_and_resolved():
    rule_xml = _base_rule(
        "fallback-interface",
        """
        <source-translation><dynamic-ip>
          <translated-address><member>pool1</member></translated-address>
          <fallback><interface-address>
            <interface>ethernet1/1</interface>
            <ip>203.0.113.1/24</ip>
            <ipv6>2001:db8::1/64</ipv6>
            <floating-ip>198.51.100.5</floating-ip>
          </interface-address></fallback>
        </dynamic-ip></source-translation>
        """,
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    details = rule.source_attributes["pan_source_translation_fallback_details"][
        "interface_address"
    ]

    assert rule.source_translation_mode != NATTranslationMode.INTERFACE_ADDRESS
    assert details["interface"] == "ethernet1/1"
    assert details["resolved_interface"] == "ethernet1/1"
    assert details["ipv4_addresses"] == ["203.0.113.1/24"]
    assert details["ipv6_addresses"] == ["2001:db8::1/64"]
    assert details["floating_ips"] == ["198.51.100.5"]
    assert "source-translation-fallback" in rule.review_reasons


def test_persistent_dipp_interface_address_sets_authoritative_interface_mode():
    rule_xml = _base_rule(
        "persistent-interface",
        """
        <source-translation><persistent-dynamic-ip-and-port><interface-address>
          <interface>ethernet1/1</interface>
          <ip>203.0.113.1/24</ip>
        </interface-address></persistent-dynamic-ip-and-port></source-translation>
        """,
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]

    assert rule.source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT
    assert rule.source_attributes["pan_persistent_dipp"] is True
    assert rule.source_attributes["pan_interface_address_details"]["resolution"] == "resolved"


def test_panorama_interface_address_keeps_context_dependent_reference_explicit():
    rule_xml = _base_rule(
        "panorama-interface",
        """
        <source-translation><dynamic-ip-and-port><interface-address>
          <interface>ethernet1/1</interface>
          <ip>203.0.113.1/24</ip>
        </interface-address></dynamic-ip-and-port></source-translation>
        """,
    )
    result = _extract(rule_xml, panorama=True)
    rule = result.canonical_ir.nat_rules[0]
    details = rule.source_attributes["pan_interface_address_details"]

    assert details["interface"] == "ethernet1/1"
    assert details["resolution"] == "context-dependent"
    assert "resolved_interface" not in details
    assert "unresolved-interface-address-interface" not in rule.review_reasons


def test_invalid_interface_address_value_is_preserved_and_requires_review():
    rule_xml = _base_rule(
        "bad-interface-address",
        """
        <source-translation><dynamic-ip-and-port><interface-address>
          <interface>ethernet1/1</interface>
          <ipv6>not-an-ipv6-address</ipv6>
        </interface-address></dynamic-ip-and-port></source-translation>
        """,
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    details = rule.source_attributes["pan_interface_address_details"]

    assert details["ipv6_addresses"] == ["not-an-ipv6-address"]
    assert details["value_validation"]["ipv6_addresses"][0]["valid"] is False
    assert details["invalid_values"][0]["value"] == "not-an-ipv6-address"
    assert "invalid-interface-address-value" in rule.review_reasons
    assert rule.requires_manual_review is True
