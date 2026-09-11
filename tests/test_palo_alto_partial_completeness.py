from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def test_panos_partial_interface_zone_and_schedule_semantics_are_lossless_and_safe():
    xml = """
    <config version="11.2.0">
      <devices>
        <entry name="localhost.localdomain">
          <network>
            <interface>
              <aggregate-ethernet>
                <entry name="ae1">
                  <layer3>
                    <ip>
                      <entry name="10.0.0.1/24"/>
                      <entry name="10.0.0.2/24"/>
                    </ip>
                    <mtu>1500</mtu>
                  </layer3>
                </entry>
              </aggregate-ethernet>
              <ethernet>
                <entry name="ethernet1/1">
                  <aggregate-group>ae1</aggregate-group>
                </entry>
              </ethernet>
            </interface>
          </network>
          <vsys>
            <entry name="vsys1">
              <zone>
                <entry name="trust">
                  <enable-user-identification>yes</enable-user-identification>
                  <enable-device-identification>yes</enable-device-identification>
                  <network>
                    <layer3><member>ae1</member></layer3>
                    <zone-protection-profile>zp-trust</zone-protection-profile>
                    <enable-packet-buffer-protection>yes</enable-packet-buffer-protection>
                    <log-setting>zone-log</log-setting>
                    <net-inspection>yes</net-inspection>
                  </network>
                </entry>
              </zone>
              <schedule>
                <entry name="work-hours">
                  <schedule-type>
                    <recurring>
                      <weekly>
                        <monday>
                          <member>08:00-12:00</member>
                          <member>13:00-17:00</member>
                        </monday>
                        <tuesday><member>09:00-11:00</member></tuesday>
                      </weekly>
                    </recurring>
                  </schedule-type>
                </entry>
              </schedule>
            </entry>
          </vsys>
        </entry>
      </devices>
    </config>
    """

    result = PANOSSourceParser().extract(xml)
    interfaces = {item.name: item for item in result.canonical_ir.interfaces}

    ae1 = interfaces["ae1"]
    assert ae1.ip == "10.0.0.1/24"
    assert [item.address for item in ae1.additional_ipv4_addresses] == ["10.0.0.2/24"]
    assert ae1.secondary_ips == []
    assert ae1.source_attributes["pan_additional_ipv4_addresses"] == ["10.0.0.2/24"]
    assert ae1.mtu == 1500
    assert "ethernet1/1" in ae1.members

    member = interfaces["ethernet1/1"]
    assert member.source_aggregate_parent == "ae1"
    assert member.source_attributes["pan_effective_interface_type"] == "ethernet:unconfigured"

    trust = next(zone for zone in result.canonical_ir.zones if zone.name == "trust")
    assert trust.source_context is None
    assert trust.source_attributes["pan_source_context"] == "vsys:vsys1"
    assert trust.zone_type == "layer3"
    assert trust.source_log_setting == "zone-log"
    assert trust.source_user_identification_enabled is True
    assert trust.source_attributes["pan_zone_protection_profile_value"] == "zp-trust"
    assert trust.source_attributes["pan_enable_packet_buffer_protection_value"] == "yes"
    assert trust.source_attributes["pan_net_inspection_value"] == "yes"

    schedule = next(item for item in result.canonical_ir.schedules if item.name == "work-hours")
    assert schedule.schedule_type == "source-only"
    assert schedule.recurrence["kind"] == "weekly"
    assert len(schedule.windows) == 3
    assert {
        (window["day"], window["start"], window["end"])
        for window in schedule.windows
    } == {
        ("monday", "08:00", "12:00"),
        ("monday", "13:00", "17:00"),
        ("tuesday", "09:00", "11:00"),
    }


def test_panos_security_rule_preserves_panorama_target_tags_and_profile_audit():
    xml = """
    <config version="12.1.0">
      <shared><tag><entry name="prod"/></tag></shared>
      <device-group>
        <entry name="DG1">
          <profiles><virus><entry name="av1"/></virus></profiles>
          <profile-group>
            <entry name="pg1"><virus><member>av1</member></virus></entry>
          </profile-group>
          <pre-rulebase>
            <security><rules>
              <entry name="allow-web">
                <from><member>trust</member></from>
                <to><member>untrust</member></to>
                <source><member>any</member></source>
                <destination><member>any</member></destination>
                <application><member>any</member></application>
                <service><member>application-default</member></service>
                <category><member>any</member></category>
                <action>allow</action>
                <tag><member>prod</member></tag>
                <profile-setting><group><member>pg1</member></group></profile-setting>
                <target>
                  <devices>
                    <entry name="001122334455"><vsys><entry name="vsys1"/></vsys></entry>
                  </devices>
                  <negate>no</negate>
                </target>
              </entry>
            </rules></security>
          </pre-rulebase>
        </entry>
      </device-group>
    </config>
    """

    result = PANOSSourceParser().extract(xml)
    policy = next(item for item in result.canonical_ir.policies if item.name == "allow-web")

    assert policy.source_extra_settings["pan_url_categories"] == ["any"]
    assert policy.source_extra_settings["pan_resolved_tags"] == ["prod"]
    assert policy.source_security_profile_references["profile-group[0]"] == "pg1"
    assert policy.security_profile_reference_statuses["profile-group[0]"] == "resolved"

    target = policy.source_extra_settings["pan_target"]
    assert target["negate"] == "no"
    assert target["devices"][0]["name"] == "001122334455"
    assert target["devices"][0]["vsys"] == ["vsys1"]
    assert "target" not in policy.source_extra_settings.get("pan_unknown_fields", {})
    assert "panorama-target-context" in policy.review_reasons


def test_panos_nat_special_translation_semantics_and_interface_reference():
    xml = """
    <config version="12.1.0">
      <devices>
        <entry name="localhost.localdomain">
          <network>
            <interface><ethernet>
              <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.1/24"/></ip></layer3></entry>
            </ethernet></interface>
          </network>
          <vsys><entry name="vsys1">
            <tag><entry name="prod"/></tag>
            <address><entry name="pool1"><ip-netmask>203.0.113.10/32</ip-netmask></entry></address>
            <rulebase><nat><rules>
              <entry name="twice-ifaddr">
                <from><member>trust</member></from><to><member>untrust</member></to>
                <source><member>any</member></source><destination><member>any</member></destination>
                <service>any</service><to-interface>ethernet1/1</to-interface><tag><member>prod</member></tag>
                <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface><ip>203.0.113.1/24</ip></interface-address></dynamic-ip-and-port></source-translation>
                <destination-translation><translated-address>10.0.0.10</translated-address><translated-port>443</translated-port></destination-translation>
              </entry>
              <entry name="dynamic-fallback">
                <from><member>trust</member></from><to><member>untrust</member></to>
                <source><member>any</member></source><destination><member>any</member></destination><service>any</service>
                <source-translation><dynamic-ip><translated-address><member>pool1</member></translated-address><fallback><interface-address><interface>ethernet1/1</interface></interface-address></fallback></dynamic-ip></source-translation>
              </entry>
              <entry name="static-bi">
                <from><member>trust</member></from><to><member>untrust</member></to>
                <source><member>any</member></source><destination><member>any</member></destination><service>any</service>
                <source-translation><static-ip><translated-address>203.0.113.20</translated-address><bi-directional>yes</bi-directional></static-ip></source-translation>
              </entry>
              <entry name="persistent-dipp">
                <from><member>trust</member></from><to><member>untrust</member></to>
                <source><member>any</member></source><destination><member>any</member></destination><service>any</service>
                <source-translation><persistent-dynamic-ip-and-port><translated-address><member>pool1</member></translated-address></persistent-dynamic-ip-and-port></source-translation>
              </entry>
              <entry name="bad-port">
                <from><member>trust</member></from><to><member>untrust</member></to>
                <source><member>any</member></source><destination><member>any</member></destination><service>any</service>
                <destination-translation><translated-address>10.0.0.20</translated-address><translated-port>70000</translated-port></destination-translation>
              </entry>
            </rules></nat></rulebase>
          </entry></vsys>
        </entry>
      </devices>
    </config>
    """

    result = PANOSSourceParser().extract(xml)
    rules = {item.name: item for item in result.canonical_ir.nat_rules}

    twice = rules["twice-ifaddr"]
    assert twice.source_attributes["pan_to_interface_resolution"] == "resolved"
    assert twice.source_attributes["pan_resolved_to_interface"] == "ethernet1/1"
    assert twice.source_attributes["pan_interface_address_details"]["interface"] == "ethernet1/1"
    assert twice.translated_destination_ports[0].start == 443
    assert "to-interface" not in twice.review_reasons
    assert "tag" not in twice.review_reasons

    fallback = rules["dynamic-fallback"]
    assert fallback.source_pool_references == ["pool1"]
    assert fallback.source_attributes["pan_source_translation_fallback_details"]["interface_address"]["interface"] == "ethernet1/1"

    static = rules["static-bi"]
    assert static.source_attributes["pan_static_ip_bi_directional"] is True
    assert static.source_attributes["pan_static_ip_bi_directional_raw"] == "yes"

    persistent = rules["persistent-dipp"]
    assert persistent.source_attributes["pan_persistent_dipp"] is True
    assert persistent.source_pool_references == ["pool1"]

    bad_port = rules["bad-port"]
    assert bad_port.source_attributes["pan_invalid_translated_port"] == "70000"
    assert "invalid-translated-port" in bad_port.review_reasons
    assert [rule.sequence for rule in result.canonical_ir.nat_rules] == [0, 1, 2, 3, 4]


def test_panos_panorama_template_interfaces_keep_stack_vsys_and_zone_context():
    xml = """
    <config version="12.1.0">
      <template><entry name="T1"><config><devices><entry name="localhost.localdomain">
        <network><interface><ethernet><entry name="ethernet1/2"><layer3><ip>
          <entry name="192.0.2.1/24"/><entry name="192.0.2.2/24"/>
        </ip></layer3></entry></ethernet></interface></network>
        <vsys><entry name="vsys1">
          <import><network><interface><member>ethernet1/2</member></interface></network></import>
          <zone><entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone>
        </entry></vsys>
      </entry></devices></config></entry></template>
      <template-stack><entry name="Stack1">
        <templates><member>T1</member></templates>
        <devices><entry name="001122334455"/></devices>
      </entry></template-stack>
    </config>
    """

    result = PANOSSourceParser().extract(xml)
    interface = next(
        item for item in result.canonical_ir.interfaces
        if item.name == "ethernet1/2" and item.source_context == "template:T1"
    )

    assert interface.ip == "192.0.2.1/24"
    assert interface.secondary_ips == []
    assert interface.source_attributes["pan_additional_ipv4_addresses"] == ["192.0.2.2/24"]
    assert interface.source_attributes["pan_vsys_associations"] == ["vsys1"]
    assert interface.source_attributes["pan_template_stacks"][0]["name"] == "Stack1"
    assert interface.source_attributes["pan_template_stacks"][0]["devices"] == ["001122334455"]
    assert interface.source_attributes["pan_template_zones"][0]["zone"] == "trust"
    assert interface.zone == "trust"
