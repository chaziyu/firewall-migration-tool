from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import NATTranslationMode, NATType
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _extract(body: str):
    return PANOSSourceParser().extract(f"<config version='11.1.0'>{body}</config>")


def _match_fields(service: str = "service-https") -> str:
    return f"""
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <service>{service}</service>
    """


def test_nat_direct_scalar_service_translation_and_rulebase_provenance():
    result = _extract(f"""
      <devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
        <address><entry name='pool'><ip-netmask>203.0.113.8/32</ip-netmask></entry></address>
        <pre-rulebase><nat><rules><entry name='duplicate'>
          {_match_fields()}<source-translation><dynamic-ip-and-port>
            <translated-address><member>pool</member></translated-address>
          </dynamic-ip-and-port></source-translation>
        </entry></rules></nat></pre-rulebase>
        <rulebase><nat><rules><entry name='duplicate'>
          {_match_fields()}<destination-translation>
            <translated-address>pool</translated-address><translated-port>8443</translated-port>
          </destination-translation><disabled>yes</disabled>
        </entry></rules></nat></rulebase>
        <post-rulebase><nat><rules><entry name='duplicate'>
          {_match_fields()}<dynamic-destination-translation>
            <translated-address>pool</translated-address><translated-port>9443</translated-port>
            <distribution><round-robin/></distribution>
          </dynamic-destination-translation>
        </entry></rules></nat></post-rulebase>
      </entry></vsys></entry></devices>
    """)
    assert len(result.canonical_ir.nat_rules) == 3
    pre, local, post = result.canonical_ir.nat_rules
    assert pre.services == ["service-https"]
    assert pre.source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT
    assert pre.translated_sources == ["pool"]
    assert local.type == NATType.DESTINATION
    assert local.translated_port == "8443"
    assert local.enabled is False
    assert post.translated_port == "9443"
    assert post.source_attributes["pan_destination_distribution"]
    assert [rule.source_attributes["pan_rulebase_position"] for rule in (pre, local, post)] == ["pre", "local", "post"]
    assert len({rule.source_rule_id for rule in (pre, local, post)}) == 3


def test_interface_address_nat_and_unknown_fields_are_partial_not_normalized():
    result = _extract(f"""
      <devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
        <rulebase><nat><rules><entry name='interface-snat'>
          {_match_fields()}<to-interface>ethernet1/1</to-interface>
          <source-translation><dynamic-ip-and-port><interface-address>
            <interface>ethernet1/1</interface><ip>198.51.100.2/32</ip><floating-ip>198.51.100.3</floating-ip>
          </interface-address></dynamic-ip-and-port></source-translation>
          <future-setting><enabled>yes</enabled></future-setting>
        </entry></rules></nat></rulebase>
      </entry></vsys></entry></devices>
    """)
    rule = result.canonical_ir.nat_rules[0]
    assert rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert rule.migration_status == "PARTIALLY_NORMALIZED"
    assert rule.requires_manual_review
    assert rule.source_attributes["pan_interface_address"]
    assert rule.source_attributes["pan_unknown_fields"]
    item = next(item for item in result.inventory_items if item.domain == "nat")
    assert item.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_static_routes_are_discovered_only_from_device_network_and_keep_vr_semantics():
    result = _extract("""
      <devices><entry name='localhost.localdomain'><network><virtual-router>
        <entry name='vr-a'><routing-table><ip><static-route>
          <entry name='default'><destination>0.0.0.0/0</destination>
            <nexthop><ip-address>192.0.2.1</ip-address></nexthop><interface>ethernet1/1</interface>
          </entry>
          <entry name='discard'><destination>198.51.100.0/24</destination><nexthop><discard/></nexthop>
            <metric>20</metric><bfd><profile>default</profile></bfd>
            <path-monitor><enable>yes</enable></path-monitor>
          </entry>
        </static-route></ip></routing-table></entry>
        <entry name='vr-b'><routing-table><ipv6><static-route>
          <entry name='v6'><destination>2001:db8::/32</destination>
            <nexthop><next-vr>vr-a</next-vr></nexthop>
          </entry>
        </static-route></ipv6></routing-table></entry>
      </virtual-router></network><vsys><entry name='vsys1'><zone/></entry></vsys></entry></devices>
    """)
    assert len(result.canonical_ir.routes) == 3
    default, discard, v6 = result.canonical_ir.routes
    assert default.metric is None
    assert default.source_context.endswith("virtual-router:vr-a")
    assert discard.blackhole is True
    assert discard.source_attributes["pan_bfd"]
    assert discard.migration_status == "PARTIALLY_NORMALIZED"
    assert v6.address_family == "ipv6"
    assert v6.next_hop == "vr-a"
    assert v6.source_attributes["pan_next_hop_type"] == "next-vr"


def test_vsys_network_imports_are_structured_and_associated():
    result = _extract("""
      <devices><entry name='localhost.localdomain'>
        <network><interface><ethernet><entry name='ethernet1/1'><layer3>
          <ip><entry name='192.0.2.2/24'/></ip>
        </layer3></entry></ethernet></interface>
        <virtual-router><entry name='default'><routing-table><ip><static-route>
          <entry name='r'><destination>203.0.113.0/24</destination><nexthop><discard/></nexthop></entry>
        </static-route></ip></routing-table></entry></virtual-router></network>
        <vsys><entry name='vsys1'><import><network>
          <interface><member>ethernet1/1</member></interface>
          <virtual-router><member>default</member></virtual-router>
          <logical-router><member>lr-1</member></logical-router>
          <vlan><member>vlan.10</member></vlan><virtual-wire><member>vw-1</member></virtual-wire>
        </network></import></entry></vsys>
      </entry></devices>
    """)
    assert result.canonical_ir.interfaces[0].source_attributes["pan_imported_by_vsys"] == ["vsys1"]
    assert result.canonical_ir.routes[0].source_attributes["pan_imported_by_vsys"] == ["vsys1"]
    imports = [item for item in result.inventory_items if item.domain == "vsys_network_import"]
    assert len(imports) == 5
    assert all(item.status == ExtractionStatus.VENDOR_EXTENSION for item in imports)


def test_panorama_parent_resolution_shadowing_and_invalid_hierarchy_findings():
    result = _extract("""
      <shared><address><entry name='Inherited'><ip-netmask>10.0.0.1/32</ip-netmask></entry></address></shared>
      <devices><entry name='localhost.localdomain'><device-group>
        <entry name='parent'><address><entry name='Inherited'><ip-netmask>10.0.0.2/32</ip-netmask></entry></address></entry>
        <entry name='child'><parent-dg>parent</parent-dg><pre-rulebase><security><rules>
          <entry name='uses-parent'><from><member>any</member></from><to><member>any</member></to>
            <source><member>Inherited</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service><action>allow</action>
          </entry>
        </rules></security></pre-rulebase></entry>
        <entry name='orphan'><parent-dg>missing</parent-dg></entry>
        <entry name='cycle-a'><parent-dg>cycle-b</parent-dg></entry>
        <entry name='cycle-b'><parent-dg>cycle-a</parent-dg></entry>
      </device-group></entry></devices>
    """)
    policy = result.canonical_ir.policies[0]
    assert policy.source == ["parent::Inherited"]
    findings = [item for item in result.inventory_items if item.domain == "panorama_hierarchy"]
    assert any("does not exist" in note for item in findings for note in item.notes)
    assert any("cycle detected" in note for item in findings for note in item.notes)


def test_unhandled_policy_families_default_rules_and_profile_groups_have_one_outcome():
    result = _extract("""
      <devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>
        <profile-group><entry name='profiles'><description>all profiles</description>
          <virus><member>av</member></virus><data-filtering><member>dlp</member></data-filtering>
        </entry></profile-group>
        <rulebase>
          <default-security-rules><rules><entry name='intrazone-default'>
            <action>allow</action><log-end>yes</log-end><option><disable-server-response-inspection>yes</disable-server-response-inspection></option>
          </entry></rules></default-security-rules>
          <application-override><rules><entry name='app-override'><protocol>tcp</protocol></entry></rules></application-override>
          <future-policy><rules><entry name='future'><new-setting>value</new-setting></entry></rules></future-policy>
        </rulebase>
      </entry></vsys></entry></devices>
    """)
    profile_items = [item for item in result.inventory_items if item.domain == "profile_groups"]
    assert len(profile_items) == 1
    assert profile_items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    defaults = [item for item in result.inventory_items if item.domain == "default_security_rules"]
    assert len(defaults) == 1 and defaults[0].status == ExtractionStatus.EXTRACT_ONLY
    assert defaults[0].source_attributes["pan_option"]
    policy_family_items = [item for item in result.inventory_items if item.domain.startswith("policy:")]
    assert {item.domain for item in policy_family_items} == {"policy:application-override", "policy:future-policy"}
    assert next(item for item in policy_family_items if item.domain == "policy:application-override").status == ExtractionStatus.EXTRACT_ONLY
    assert next(item for item in policy_family_items if item.domain == "policy:future-policy").status == ExtractionStatus.UNSUPPORTED


def test_zone_security_settings_and_multiple_types_force_partial():
    result = _extract("""
      <devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'><zone>
        <entry name='mixed'><network><layer3><member>ethernet1/1</member></layer3>
          <tap><member>ethernet1/2</member></tap></network>
          <enable-user-identification>yes</enable-user-identification>
          <zone-protection-profile>strict</zone-protection-profile><future-setting>yes</future-setting>
        </entry>
      </zone></entry></vsys></entry></devices>
    """)
    zone = result.canonical_ir.zones[0]
    assert zone.migration_status == "PARTIALLY_NORMALIZED"
    assert zone.source_attributes["pan_zone_types"] == ["layer3", "tap"]
    assert zone.source_attributes["pan_enable_user_identification"]
    item = next(item for item in result.inventory_items if item.domain == "zones")
    assert item.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_pan_os_response_wrapper_is_unwrapped_safely():
    result = PANOSSourceParser().extract(
        "<response status='success'><result><config version='11.1.0'><shared/></config></result></response>"
    )
    assert result.canonical_ir.metadata.source_version == "11.1.0"
