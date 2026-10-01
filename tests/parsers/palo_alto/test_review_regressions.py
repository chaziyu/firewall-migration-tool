from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.validation import validate_panos_config


def _analyze(xml: str):
    config = build_panos_config(xml)
    derived = build_derived_views(config)
    validation = validate_panos_config(config, derived)
    return config, derived, validation


def test_custom_threat_vulnerability_is_not_typed_as_vulnerability_profile():
    config = build_panos_config("""<config><shared>
      <threats><vulnerability><entry name='custom-threat'><severity>critical</severity></entry></vulnerability></threats>
      <profiles><vulnerability><entry name='profile'/></vulnerability></profiles>
    </shared></config>""")

    assert [item.name for item in config.vulnerability_profiles] == ["profile"]
    custom = next(item for item in config.source_inventory if item.name == "custom-threat")
    assert "/threats/vulnerability/entry" in custom.source_path


def test_unknown_nat_source_translation_is_preserved_and_reported():
    config, _, validation = _analyze("""<config><shared><rulebase><nat><rules>
      <entry name='future-snat'>
        <source-translation><future-mode><pool>pool-a</pool></future-mode></source-translation>
      </entry>
    </rules></nat></rulebase></shared></config>""")

    rule = config.nat_rules[0]
    assert rule.source_translation is None
    assert rule.raw_extra["source-translation"]["future-mode"] == {"pool": "pool-a"}
    assert any("unsupported source-translation" in issue.message for issue in validation.issues)
    assert not any(issue.message == "NAT rule has no explicit translation branch" for issue in validation.issues)


def test_member_lists_ignore_unknown_children_and_preserve_them_as_raw_source():
    config = build_panos_config("""<config><shared><rulebase><security><rules>
      <entry name='allow'>
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>192.0.2.1</member><future>do-not-reference</future></source>
        <destination><member>any</member></destination><action>allow</action>
      </entry>
    </rules></security></rulebase></shared></config>""")

    rule = config.security_rules[0]
    assert rule.source == ["192.0.2.1"]
    assert rule.raw_extra["nested"]["source"]["future"] == "do-not-reference"


def test_interface_validation_checks_prefix_length_and_address_family():
    _, _, validation = _analyze("""<config><devices><entry name='fw'><network><interface><ethernet>
      <entry name='ethernet1/1'><layer3>
        <ip><entry name='192.0.2.1/99'/></ip>
        <ipv6><address><entry name='2001:db8::1/129'/></address></ipv6>
      </layer3></entry>
    </ethernet></interface></network></entry></devices></config>""")

    messages = [issue.message for issue in validation.issues if issue.domain == "interface"]
    assert "malformed IPv4 address: '192.0.2.1/99'" in messages
    assert "malformed IPv6 address: '2001:db8::1/129'" in messages


def test_static_route_duplicate_identity_includes_source_scope():
    xml = """<config><devices>
      <entry name='fw-a'><network><virtual-router><entry name='vr-main'><routing-table><ip><static-route>
        <entry name='default'><destination>0.0.0.0/0</destination></entry>
      </static-route></ip></routing-table></entry></virtual-router></network></entry>
      <entry name='fw-b'><network><virtual-router><entry name='vr-main'><routing-table><ip><static-route>
        <entry name='default'><destination>0.0.0.0/0</destination></entry>
      </static-route></ip></routing-table></entry></virtual-router></network></entry>
    </devices></config>"""
    _, _, validation = _analyze(xml)

    assert not any("duplicate static route name" in issue.message for issue in validation.issues)

    _, _, duplicate_validation = _analyze("""<config><devices><entry name='fw'><network>
      <virtual-router><entry name='vr-main'><routing-table><ip><static-route>
        <entry name='default'><destination>0.0.0.0/0</destination></entry>
        <entry name='default'><destination>10.0.0.0/8</destination></entry>
      </static-route></ip></routing-table></entry></virtual-router>
    </network></entry></devices></config>""")
    assert any("duplicate static route name 'default'" in issue.message for issue in duplicate_validation.issues)


def test_unknown_route_nexthop_subtree_is_preserved():
    config = build_panos_config("""<config><devices><entry name='fw'><network>
      <virtual-router><entry name='vr-main'><routing-table><ip><static-route>
        <entry name='future'><destination>10.0.0.0/8</destination>
          <nexthop><future-hop><target>edge-a</target></future-hop></nexthop>
        </entry>
      </static-route></ip></routing-table></entry></virtual-router>
    </network></entry></devices></config>""")

    route = config.virtual_routers[0].static_routes[0]
    assert route.nexthop_type == "future-hop"
    assert route.raw_extra["nexthop"]["future-hop"] == {"target": "edge-a"}


def test_device_group_visibility_does_not_cross_panorama_device_owners():
    _, derived, _ = _analyze("""<config><devices>
      <entry name='pan-a'><device-group>
        <entry name='parent'/>
        <entry name='child'><parent-dg>parent</parent-dg>
          <pre-rulebase><security><rules><entry name='allow'>
            <from><member>any</member></from><to><member>any</member></to>
            <source><member>web</member></source><destination><member>any</member></destination>
            <action>allow</action>
          </entry></rules></security></pre-rulebase>
        </entry>
      </device-group></entry>
      <entry name='pan-b'><device-group>
        <entry name='parent'><address><entry name='web'><ip-netmask>192.0.2.10/32</ip-netmask></entry></address></entry>
        <entry name='child'><parent-dg>parent</parent-dg></entry>
      </device-group></entry>
    </devices></config>""")

    resolution = next(
        item for item in derived.reference_resolutions
        if item.owner_name == "allow" and item.owner_field == "source" and item.reference_name == "web"
    )
    assert resolution.status == "UNRESOLVED"


def test_validation_reports_contradictory_native_choice_branches_without_repair():
    config, _, validation = _analyze("""<config><shared>
      <address><entry name='multi'><ip-netmask>192.0.2.1/32</ip-netmask><fqdn>example.test</fqdn></entry></address>
      <address-group><entry name='both'><static><member>multi</member></static><dynamic><filter>'tag-a'</filter></dynamic></entry></address-group>
      <service><entry name='both-protocols'><protocol>
        <tcp><port>80</port></tcp><udp><port>53</port></udp>
      </protocol></entry></service>
    </shared></config>""")

    messages = {issue.message for issue in validation.issues}
    assert any(message.startswith("address has multiple explicit value types") for message in messages)
    assert "address group has both static and dynamic source branches" in messages
    assert "service has both TCP and UDP protocol branches" in messages

    address = config.addresses[0]
    group = config.address_groups[0]
    service = config.services[0]
    assert (address.ip_netmask, address.fqdn) == ("192.0.2.1/32", "example.test")
    assert group.static_members == ["multi"] and group.dynamic_filter == "'tag-a'"
    assert service.tcp.port == "80" and service.udp.port == "53"


def test_schedule_validation_reports_invalid_time_and_date_ranges():
    _, _, validation = _analyze("""<config><shared><schedule>
      <entry name='bad-time'><schedule-type><recurring><daily><member>25:00-26:00</member></daily></recurring></schedule-type></entry>
      <entry name='bad-date'><schedule-type><non-recurring><member>2026/99/01@08:00-2026/99/01@17:00</member></non-recurring></schedule-type></entry>
    </schedule></shared></config>""")

    messages = {issue.message for issue in validation.issues if issue.domain == "schedule"}
    assert "malformed daily schedule range: '25:00-26:00'" in messages
    assert "malformed non-recurring schedule range: '2026/99/01@08:00-2026/99/01@17:00'" in messages
