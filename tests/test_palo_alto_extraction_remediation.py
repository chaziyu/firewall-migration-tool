from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import NATTranslationMode
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _extract(body: str):
    return PANOSSourceParser().extract(f"<config version='11.1.0'>{body}</config>")


def _security_match(application: str | None = "any", source: str = "any") -> str:
    application_xml = (
        f"<application><member>{application}</member></application>"
        if application is not None else ""
    )
    return f"""
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>{source}</member></source><destination><member>any</member></destination>
      {application_xml}<service><member>any</member></service><action>allow</action>
    """


def test_security_rule_without_application_is_accounted_for_and_withheld():
    result = _extract(f"""
      <devices><entry name='fw-a'><vsys><entry name='vsys1'><rulebase>
        <security><rules><entry name='missing-app'>{_security_match(None)}</entry></rules></security>
      </rulebase></entry></vsys></entry></devices>
    """)

    assert result.canonical_ir.policies == []
    item = next(item for item in result.inventory_items
                if item.domain == "policies" and item.name == "missing-app")
    assert item.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert "application" in item.notes[0]
    assert result.generation_safe is False


def test_routing_instance_discovery_preserves_logical_router_vrf_hierarchy():
    result = _extract(f"""
      <devices><entry name='serial-a'><network>
        <virtual-router><entry name='vr-a'>
          <routing-table><ip><static-route><entry name='vr-route'>
            <destination>203.0.113.0/24</destination><nexthop><discard/></nexthop>
          </entry></static-route></ip></routing-table>
          <protocol><bgp><local-as>65001</local-as></bgp></protocol>
        </entry></virtual-router>
        <logical-router><entry name='lr-a'><vrf><entry name='blue'>
          <routing-table><ipv6><static-route><entry name='lr-route'>
            <destination>2001:db8:10::/64</destination><nexthop><next-vr>blue</next-vr></nexthop>
          </entry></static-route></ipv6></routing-table>
          <routing-protocol><ospf><router-id>192.0.2.10</router-id>
            <area><entry name='0.0.0.0'><interface><entry name='ethernet1/1'/></interface></entry></area>
          </ospf></routing-protocol>
        </entry></vrf></entry></logical-router>
      </network></entry></devices>
    """)

    route = next(route for route in result.canonical_ir.routes if route.name == "lr-route")
    assert route.source_attributes["pan_routing_instance_type"] == "logical-router-vrf"
    assert route.source_attributes["pan_logical_router"] == "lr-a"
    assert route.source_attributes["pan_vrf"] == "blue"
    assert "/logical-router/entry[@name='lr-a']/vrf/entry[@name='blue']" in route.source_attributes["pan_source_path"]
    dynamic = next(item for item in result.inventory_items
                    if item.domain == "dynamic_routing:ospf")
    assert dynamic.source_attributes["routing_instance_type"] == "logical-router-vrf"
    assert dynamic.source_attributes["logical_router_name"] == "lr-a"
    assert dynamic.source_attributes["vrf_name"] == "blue"
    assert dynamic.source_attributes["pan_device_serial"] == "serial-a"


def test_interface_mss_ndp_and_physical_settings_are_explicit_source_evidence():
    result = _extract("""
      <devices><entry name='fw-a'><network><interface><ethernet><entry name='ethernet1/1'>
        <aggregate-group>ae1</aggregate-group><lacp><enable>yes</enable></lacp>
        <fec><mode>fc-fec</mode></fec><poe><enable>yes</enable></poe>
        <layer3><ip><entry name='192.0.2.2/24'/></ip>
          <adjust-tcp-mss><enable>yes</enable><ipv4><mss-adjustment>1300</mss-adjustment></ipv4></adjust-tcp-mss>
          <ndp-proxy><enable>yes</enable><address><member>2001:db8::1</member></address></ndp-proxy>
        </layer3>
      </entry></ethernet></interface></network></entry></devices>
    """)

    interface = result.canonical_ir.interfaces[0]
    attrs = interface.source_attributes
    assert attrs["pan_adjust_tcp_mss_enabled"] == "yes"
    assert attrs["pan_adjust_tcp_mss_ipv4"] == "1300"
    assert attrs["pan_ndp_proxy_enabled"] == "yes"
    assert attrs["pan_ndp_proxy_addresses"] == ["2001:db8::1"]
    assert attrs["pan_aggregate_group"]
    assert attrs["pan_lacp"] and attrs["pan_fec"] and attrs["pan_poe"]
    assert interface.requires_manual_review is True
    item = next(item for item in result.inventory_items
                if item.domain == "interfaces" and item.name == "ethernet1/1")
    assert item.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_nat_translation_literals_are_not_misclassified_as_object_references():
    result = _extract("""
      <devices><entry name='fw-a'><vsys><entry name='vsys1'>
        <rulebase><nat><rules><entry name='literal-snat'>
          <from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <service>any</service><source-translation><dynamic-ip-and-port>
            <translated-address><member>203.0.113.10</member><member>203.0.113.20/30</member>
              <member>203.0.113.30-203.0.113.31</member></translated-address>
          </dynamic-ip-and-port></source-translation>
        </entry></rules></nat></rulebase>
      </entry></vsys></entry></devices>
    """)

    rule = result.canonical_ir.nat_rules[0]
    assert rule.source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT
    assert rule.translated_sources == ["203.0.113.10", "203.0.113.20/30", "203.0.113.30-203.0.113.31"]
    classifications = rule.source_attributes["pan_translated_source_values"]
    assert [value["classification"] for value in classifications] == [
        "literal-host", "literal-prefix", "literal-range"
    ]
    assert "pan_unresolved_translated_sources" not in rule.source_attributes


def test_nat64_family_is_retained_and_not_presented_as_equivalent_ipv4_nat():
    result = _extract("""
      <devices><entry name='fw-a'><vsys><entry name='vsys1'><rulebase><nat><rules>
        <entry name='nat64-rule'><from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <service>any</service><nat-type>nat64</nat-type>
          <source-translation><dynamic-ip-and-port><translated-address>203.0.113.10</translated-address>
          </dynamic-ip-and-port></source-translation>
        </entry>
      </rules></nat></rulebase></entry></vsys></entry></devices>
    """)

    rule = result.canonical_ir.nat_rules[0]
    assert rule.source_attributes["pan_nat_family"] == "nat64"
    assert "nat64-source-semantics" in rule.review_reasons
    assert rule.migration_status == "PARTIALLY_NORMALIZED"


def test_security_profiles_external_lists_vpn_and_templates_are_inventory_only():
    result = _extract("""
      <shared><external-dynamic-list><entry name='threat-list'>
        <type><url>https://example.test/list</url></type><recurring><hourly/></recurring>
      </entry></external-dynamic-list></shared>
      <template><entry name='branch-template'><config><devices><entry name='fw-a'/></devices></config></entry></template>
      <template-stack><entry name='branch-stack'><templates><member>branch-template</member></templates></entry></template-stack>
      <devices><entry name='fw-a'><network>
        <ike><crypto-profiles><ike-crypto-profiles><entry name='ike-default'><encryption><member>aes-256-cbc</member></encryption></entry></ike-crypto-profiles></crypto-profiles>
          <gateway><entry name='gw-1'><local-address><interface>ethernet1/1</interface></local-address><peer-address><ip>198.51.100.2</ip></peer-address></entry></gateway>
        </ike></network><vsys><entry name='vsys1'><profiles><virus><entry name='strict-virus'><description>strict</description></entry></virus></profiles></entry></vsys></entry></devices>
    """)

    for domain in ("external_dynamic_lists", "security_profiles", "vpn:ike_crypto_profile", "vpn:ike_gateway", "panorama_templates", "panorama_template_stacks"):
        assert any(item.domain == domain and item.status == ExtractionStatus.EXTRACT_ONLY
                   for item in result.inventory_items), domain
    assert len(result.canonical_ir.vpn_tunnels) == 1
    assert result.canonical_ir.vpn_tunnels[0].migration_status == "EXTRACT_ONLY"


def test_region_and_device_id_objects_remain_explicit_vendor_inventory():
    result = _extract("""
      <shared>
        <region><entry name='europe'><country><member>DE</member></country><exclude-list><member>RU</member></exclude-list></entry></region>
        <device-objects><entry name='managed-laptop'><device-type>laptop</device-type><os>Windows</os><tag><member>managed</member></tag></entry></device-objects>
      </shared>
    """)

    region = next(item for item in result.inventory_items if item.domain == "region_objects")
    device = next(item for item in result.inventory_items if item.domain == "device_id_objects")
    assert region.status == ExtractionStatus.EXTRACT_ONLY
    assert device.status == ExtractionStatus.EXTRACT_ONLY
    assert region.source_attributes["pan_source_entry"]
    assert device.source_attributes["pan_device_id_settings"]
    assert result.canonical_ir.addresses == []


def test_managed_vsys_identity_is_qualified_per_firewall():
    result = _extract(f"""
      <devices><entry name='panorama'><device-group><entry name='dg-a'><devices>
        <entry name='serial-a'><vsys><entry name='vsys1'><address>
          <entry name='server'><ip-netmask>10.0.0.1/32</ip-netmask></entry>
        </address><rulebase><security><rules><entry name='allow-a'>
          {_security_match('any', 'server')}
        </entry></rules></security></rulebase></entry></vsys></entry>
        <entry name='serial-b'><vsys><entry name='vsys1'><address>
          <entry name='server'><ip-netmask>10.0.1.1/32</ip-netmask></entry>
        </address><rulebase><security><rules><entry name='allow-b'>
          {_security_match('any', 'server')}
        </entry></rules></security></rulebase></entry></vsys></entry>
      </devices></entry></device-group></entry></devices>
    """)

    policies = {policy.name: policy for policy in result.canonical_ir.policies}
    assert policies["allow-a"].source == ["serial-a::vsys1::server"]
    assert policies["allow-b"].source == ["serial-b::vsys1::server"]
    assert policies["allow-a"].source_rule_id != policies["allow-b"].source_rule_id
    assert any("device:serial-a:vsys:vsys1" in context
               for context in policies["allow-a"].source_extra_settings["pan_effective_order_by_context"])
    assert any("device:serial-b:vsys:vsys1" in context
               for context in policies["allow-b"].source_extra_settings["pan_effective_order_by_context"])
