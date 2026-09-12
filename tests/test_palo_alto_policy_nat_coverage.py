from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import NATTranslationMode
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _extract(xml: str):
    return PANOSSourceParser().extract(xml)


def _security_rule(name: str, target: str = "") -> str:
    return f"""
      <entry name="{name}">
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <source-user><member>any</member></source-user>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action>
        {target}
      </entry>
    """


def _nat_rule(name: str, translation: str, target: str = "") -> str:
    return f"""
      <entry name="{name}">
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <service>any</service>
        {translation}
        {target}
      </entry>
    """


def test_external_and_tunnel_zones_are_typed_without_treating_external_members_as_interfaces():
    result = _extract("""
    <config>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="external-zone">
              <network><external><member>vsys2</member></external></network>
            </entry>
            <entry name="tunnel-zone">
              <network><tunnel/></network>
            </entry>
          </zone>
        </entry>
      </vsys>
    </config>
    """)

    zones = {zone.name: zone for zone in result.canonical_ir.zones}
    external = zones["external-zone"]
    tunnel = zones["tunnel-zone"]

    assert external.zone_type == "external"
    assert external.interfaces == []
    assert external.source_attributes["pan_external_members"] == ["vsys2"]
    assert "external" not in external.source_attributes.get("pan_network_settings", {})

    assert tunnel.zone_type == "tunnel"
    assert tunnel.source_attributes["pan_tunnel_zone_configured"] is True
    assert "tunnel" not in tunnel.source_attributes.get("pan_network_settings", {})


def test_panorama_device_target_filters_security_and_nat_effective_contexts():
    target = """
      <target>
        <devices>
          <entry name="SER1"><vsys><entry name="vsys1"/></vsys></entry>
        </devices>
        <negate>no</negate>
      </target>
    """
    security = _security_rule("targeted-security", target)
    nat = _nat_rule(
        "targeted-nat",
        """
        <source-translation>
          <static-ip>
            <translated-address>203.0.113.10</translated-address>
          </static-ip>
        </source-translation>
        """,
        target,
    )
    result = _extract(f"""
    <config>
      <device-group>
        <entry name="dg1">
          <devices>
            <entry name="SER1">
              <vsys><entry name="vsys1"><address><entry name="dummy1"><ip-netmask>10.0.0.1</ip-netmask></entry></address></entry></vsys>
            </entry>
            <entry name="SER2">
              <vsys><entry name="vsys1"><address><entry name="dummy2"><ip-netmask>10.0.0.2</ip-netmask></entry></address></entry></vsys>
            </entry>
          </devices>
          <pre-rulebase>
            <security><rules>{security}</rules></security>
            <nat><rules>{nat}</rules></nat>
          </pre-rulebase>
        </entry>
      </device-group>
    </config>
    """)

    security_item = next(
        item for item in result.inventory_items
        if item.domain == "policies" and item.name == "targeted-security"
    )
    nat_item = next(
        item for item in result.inventory_items
        if item.domain == "nat" and item.name == "targeted-nat"
    )

    for item in (security_item, nat_item):
        order = item.source_attributes["pan_effective_order_by_context"]
        applicability = item.source_attributes["pan_target_applicability_by_context"]
        assert "device:SER1:vsys:vsys1" in order
        assert "device:SER2:vsys:vsys1" not in order
        assert applicability["device:SER1:vsys:vsys1"] == "applicable"
        assert applicability["device:SER2:vsys:vsys1"] == "not-applicable"

    assert nat_item.source_attributes["pan_target"]["devices"][0]["name"] == "SER1"
    assert "target" not in nat_item.source_attributes.get("pan_unknown_fields", {})


def test_panorama_target_tags_fail_closed_when_device_tag_state_is_unavailable():
    target = """
      <target>
        <tags><member>branch-firewalls</member></tags>
      </target>
    """
    security = _security_rule("tag-targeted", target)
    result = _extract(f"""
    <config>
      <device-group>
        <entry name="dg1">
          <devices>
            <entry name="SER1">
              <vsys><entry name="vsys1"><address><entry name="dummy"><ip-netmask>10.0.0.1</ip-netmask></entry></address></entry></vsys>
            </entry>
          </devices>
          <pre-rulebase><security><rules>{security}</rules></security></pre-rulebase>
        </entry>
      </device-group>
    </config>
    """)
    item = next(item for item in result.inventory_items if item.domain == "policies" and item.name == "tag-targeted")
    context = "device:SER1:vsys:vsys1"
    assert item.source_attributes["pan_target_applicability_by_context"][context] == "unknown"
    assert item.source_attributes["pan_effective_order_by_context"][context]["effective_order_complete"] is False


def test_panorama_pushed_vsys_pre_rules_are_extracted_as_a_distinct_fail_closed_view():
    security = _security_rule("pushed-security")
    nat = _nat_rule(
        "pushed-nat",
        """
        <destination-translation>
          <translated-address>192.0.2.50</translated-address>
          <translated-port>8443</translated-port>
        </destination-translation>
        """,
    )
    result = _extract(f"""
    <config>
      <panorama>
        <vsys>
          <entry name="vsys1">
            <pre-rulebase>
              <security><rules>{security}</rules></security>
              <nat><rules>{nat}</rules></nat>
            </pre-rulebase>
          </entry>
        </vsys>
      </panorama>
    </config>
    """)

    policy = next(policy for policy in result.canonical_ir.policies if policy.name == "pushed-security")
    nat_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "pushed-nat")
    policy_item = next(item for item in result.inventory_items if item.domain == "policies" and item.name == "pushed-security")
    nat_item = next(item for item in result.inventory_items if item.domain == "nat" and item.name == "pushed-nat")

    assert policy.source_context == "panorama-vsys:vsys1"
    assert policy.source_extra_settings["pan_pushed_policy_view"] is True
    assert nat_rule.source_attributes["pan_pushed_policy_view"] is True
    assert policy_item.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert nat_item.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert policy_item.source_attributes["pan_effective_order_by_context"]["panorama-vsys:vsys1"]["effective_policy_rank"] == 0
    assert nat_item.source_attributes["pan_effective_order_by_context"]["panorama-vsys:vsys1"]["effective_policy_rank"] == 0


def test_nat_source_translation_semantics_keep_persistent_dipp_and_static_bidirectional_distinct():
    persistent = _nat_rule(
        "persistent-dipp",
        """
        <source-translation>
          <persistent-dynamic-ip-and-port>
            <translated-address><member>203.0.113.20</member></translated-address>
          </persistent-dynamic-ip-and-port>
        </source-translation>
        """,
    )
    static = _nat_rule(
        "static-bidir",
        """
        <source-translation>
          <static-ip>
            <translated-address>203.0.113.30</translated-address>
            <bi-directional>yes</bi-directional>
          </static-ip>
        </source-translation>
        """,
    )
    ordinary = _nat_rule(
        "ordinary-dipp",
        """
        <source-translation>
          <dynamic-ip-and-port>
            <translated-address><member>203.0.113.21</member></translated-address>
          </dynamic-ip-and-port>
        </source-translation>
        """,
    )
    result = _extract(f"""
    <config>
      <vsys>
        <entry name="vsys1">
          <rulebase><nat><rules>{persistent}{ordinary}{static}</rules></nat></rulebase>
        </entry>
      </vsys>
    </config>
    """)

    persistent_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "persistent-dipp")
    ordinary_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "ordinary-dipp")
    static_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "static-bidir")

    persistent_semantics = persistent_rule.source_attributes["pan_source_translation_semantics"]
    static_semantics = static_rule.source_attributes["pan_source_translation_semantics"]
    assert persistent_semantics["type"] == "persistent-dynamic-ip-and-port"
    assert persistent_semantics["persistent"] is True
    assert persistent_semantics["translated_address"] == ["203.0.113.20"]
    assert persistent_rule.source_translation_mode == NATTranslationMode.PERSISTENT_DYNAMIC_IP_AND_PORT
    assert ordinary_rule.source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT
    assert persistent_rule.source_translation_mode != ordinary_rule.source_translation_mode
    assert static_semantics["type"] == "static-ip"
    assert static_semantics["bi_directional"] is True


def test_nat_effective_order_is_marked_incomplete_when_panorama_hierarchy_is_invalid():
    nat = _nat_rule(
        "nat-with-invalid-hierarchy",
        """
        <source-translation>
          <dynamic-ip><translated-address><member>203.0.113.40</member></translated-address></dynamic-ip>
        </source-translation>
        """,
    )
    result = _extract(f"""
    <config>
      <device-group>
        <entry name="child">
          <parent-dg>missing-parent</parent-dg>
          <pre-rulebase><nat><rules>{nat}</rules></nat></pre-rulebase>
        </entry>
      </device-group>
    </config>
    """)

    hierarchy_error = next(item for item in result.inventory_items if item.domain == "panorama_hierarchy")
    nat_item = next(item for item in result.inventory_items if item.domain == "nat" and item.name == "nat-with-invalid-hierarchy")
    assert hierarchy_error.status == ExtractionStatus.PARSE_ERROR
    assert nat_item.source_attributes["effective_order_complete"] is False
    assert nat_item.source_attributes["pan_effective_order_by_context"]["device-group:child"]["effective_order_complete"] is False
