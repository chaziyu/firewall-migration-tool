from fwmigrate.ir.enums import NATFamily, NATTranslationMode, NATType
from fwmigrate.parsers.palo_alto import PANOSSourceParser


def _extract(rule_xml: str):
    xml = f"""
    <config version="12.1.0">
      <devices>
        <entry name="localhost.localdomain">
          <network>
            <interface><ethernet>
              <entry name="ethernet1/1">
                <layer3>
                  <ip><entry name="203.0.113.1/24"/></ip>
                  <ipv6><address><entry name="2001:db8:ffff::1/64"/></address></ipv6>
                </layer3>
              </entry>
            </ethernet></interface>
          </network>
          <vsys><entry name="vsys1">
            <address>
              <entry name="v6-inside"><ip-netmask>2001:db8:1::/64</ip-netmask></entry>
              <entry name="v6-dest"><ip-netmask>64:ff9b::/96</ip-netmask></entry>
              <entry name="v4-pool"><ip-netmask>203.0.113.10/32</ip-netmask></entry>
              <entry name="v4-client"><ip-netmask>198.51.100.10/32</ip-netmask></entry>
              <entry name="v4-server"><ip-netmask>192.0.2.10/32</ip-netmask></entry>
              <entry name="v6-source"><ip-netmask>2001:db8:100::10/128</ip-netmask></entry>
              <entry name="v6-server"><ip-netmask>2001:db8:200::10/128</ip-netmask></entry>
            </address>
            <rulebase><nat><rules>{rule_xml}</rules></nat></rulebase>
          </entry></vsys>
        </entry>
      </devices>
    </config>
    """
    return PANOSSourceParser().extract(xml)


def _base_rule(name: str, body: str, *, source="any", destination="any") -> str:
    return f"""
    <entry name="{name}">
      <from><member>trust</member></from>
      <to><member>untrust</member></to>
      <source><member>{source}</member></source>
      <destination><member>{destination}</member></destination>
      <service>any</service>
      {body}
    </entry>
    """


def test_nat64_ipv6_initiated_is_cross_family_source_nat():
    rule_xml = _base_rule(
        "nat64-v6-init",
        """
        <nat-type>nat64</nat-type>
        <source-translation><dynamic-ip-and-port>
          <translated-address><member>v4-pool</member></translated-address>
        </dynamic-ip-and-port></source-translation>
        """,
        source="v6-inside",
        destination="v6-dest",
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert rule.type == NATType.SOURCE
    assert rule.nat_family == NATFamily.NAT64
    assert rule.original_address_family == "ipv6"
    assert rule.translated_address_family == "ipv4"
    assert semantics["family"] == "nat64"
    assert semantics["direction"] == NATType.SOURCE.value
    assert semantics["flow"] == "ipv6-initiated"
    assert rule.source_attributes["pan_ipv6_nat_semantics_complete"] is True
    assert "nat64-source-semantics" not in rule.review_reasons
    assert "source-specific-ipv6-nat-target-semantics" in rule.review_reasons


def test_nat64_ipv4_initiated_preserves_twice_nat_direction():
    rule_xml = _base_rule(
        "nat64-v4-init",
        """
        <nat-type>nat64</nat-type>
        <source-translation><static-ip>
          <translated-address>v6-source</translated-address>
        </static-ip></source-translation>
        <destination-translation>
          <translated-address>v6-server</translated-address>
        </destination-translation>
        """,
        source="v4-client",
        destination="v4-server",
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert rule.type == NATType.TWICE
    assert rule.nat_family == NATFamily.NAT64
    assert rule.original_address_family == "ipv4"
    assert rule.translated_address_family == "ipv6"
    assert semantics["direction"] == NATType.TWICE.value
    assert semantics["flow"] == "ipv4-initiated"
    assert rule.source_attributes["pan_ipv6_nat_semantics_complete"] is True


def test_nptv6_source_translation_validates_ipv6_prefixes():
    rule_xml = _base_rule(
        "npt-source",
        """
        <nat-type>nptv6</nat-type>
        <source-translation><static-ip>
          <translated-address>2001:db8:ffff::/64</translated-address>
          <bi-directional>yes</bi-directional>
        </static-ip></source-translation>
        """,
        source="2001:db8:1::/64",
        destination="2001:db8:2::/64",
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert rule.type == NATType.SOURCE
    assert rule.nat_family == NATFamily.NAT66
    assert rule.original_address_family == "ipv6"
    assert rule.translated_address_family == "ipv6"
    assert semantics["family"] == "nptv6"
    assert semantics["direction"] == NATType.SOURCE.value
    assert semantics["translated_source"]["records"][0]["valid"] is True
    assert semantics["translated_source"]["records"][0]["prefix_length"] == 64
    assert rule.source_attributes["pan_ipv6_nat_semantics_complete"] is True
    assert "nptv6-source-semantics" not in rule.review_reasons


def test_nptv6_combined_source_and_destination_keeps_twice_direction():
    rule_xml = _base_rule(
        "npt-twice",
        """
        <nat-type>nptv6</nat-type>
        <source-translation><static-ip>
          <translated-address>2001:db8:100::/64</translated-address>
        </static-ip></source-translation>
        <destination-translation>
          <translated-address>2001:db8:200::/64</translated-address>
        </destination-translation>
        """,
        source="2001:db8:1::/64",
        destination="2001:db8:2::/64",
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert rule.type == NATType.TWICE
    assert rule.nat_family == NATFamily.NAT66
    assert semantics["direction"] == NATType.TWICE.value
    assert semantics["translated_source"]["records"][0]["valid"] is True
    assert semantics["translated_destination"]["records"][0]["valid"] is True
    assert rule.source_attributes["pan_ipv6_nat_semantics_complete"] is True


def test_nptv6_rejects_port_translation_semantically_but_preserves_value():
    rule_xml = _base_rule(
        "npt-port-invalid",
        """
        <nat-type>nptv6</nat-type>
        <destination-translation>
          <translated-address>2001:db8:200::/64</translated-address>
          <translated-port>443</translated-port>
        </destination-translation>
        """,
        source="2001:db8:1::/64",
        destination="2001:db8:2::/64",
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert semantics["translated_port"] == "443"
    assert "nptv6-port-translation-not-supported" in rule.review_reasons
    assert rule.source_attributes["pan_ipv6_nat_semantics_complete"] is False


def test_nptv6_invalid_prefix_is_preserved_and_flagged():
    rule_xml = _base_rule(
        "npt-prefix-invalid",
        """
        <nat-type>nptv6</nat-type>
        <source-translation><static-ip>
          <translated-address>2001:db8:ffff::1/128</translated-address>
        </static-ip></source-translation>
        """,
        source="2001:db8:1::/64",
        destination="2001:db8:2::/64",
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    validation = rule.source_attributes["pan_ipv6_nat_semantics"]["translated_source"]

    assert validation["records"][0]["value"] == "2001:db8:ffff::1/128"
    assert validation["records"][0]["valid"] is False
    assert "invalid-nptv6-translated-source-prefix" in rule.review_reasons
    assert rule.source_attributes["pan_ipv6_nat_semantics_complete"] is False


def test_nptv6_dynamic_interface_prefix_is_explicit_and_not_dipp():
    rule_xml = _base_rule(
        "npt-dynamic-interface",
        """
        <nat-type>nptv6</nat-type>
        <source-translation><dynamic-ip><interface-address>
          <interface>ethernet1/1</interface>
          <ipv6>2001:db8:ffff::1/64</ipv6>
        </interface-address></dynamic-ip></source-translation>
        """,
        source="2001:db8:1::/64",
        destination="2001:db8:2::/64",
    )
    result = _extract(rule_xml)
    rule = result.canonical_ir.nat_rules[0]
    semantics = rule.source_attributes["pan_ipv6_nat_semantics"]

    assert rule.nat_family == NATFamily.NAT66
    assert rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert semantics["dynamic_interface_prefix"] is True
    assert semantics["source_translation_mode"] == NATTranslationMode.INTERFACE_ADDRESS.value
    assert "nptv6-unsupported-source-translation-mode" not in rule.review_reasons
