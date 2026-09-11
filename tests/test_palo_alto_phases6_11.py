from textwrap import dedent

from fwmigrate.ir.migrations import migrate_ir_payload
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def test_static_route_path_monitor_preserves_repeated_destinations_and_bfd_separately():
    result = PANOSSourceParser().extract(dedent("""
        <config>
          <devices><entry name="fw-a">
            <network>
              <interface><ethernet>
                <entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry>
              </ethernet></interface>
              <virtual-router><entry name="vr1">
                <routing-table><ip><static-route><entry name="default-monitor">
                  <destination>0.0.0.0/0</destination>
                  <bfd><profile>strict-bfd</profile></bfd>
                  <path-monitor>
                    <enable>yes</enable><failure-condition>all</failure-condition>
                    <hold-time>10</hold-time><recovery-time>20</recovery-time><preemptive>no</preemptive>
                    <monitor-dest><entry name="primary"><destination>monitor-ip</destination><interval>5</interval><count>2</count></entry>
                    <entry name="secondary"><destination>198.51.100.2</destination><interval>10</interval><count>3</count></entry></monitor-dest>
                  </path-monitor>
                </entry></static-route></ip></routing-table>
              </entry></virtual-router>
            </network>
            <vsys><entry name="vsys1">
              <address><entry name="monitor-ip"><ip-netmask>203.0.113.7/32</ip-netmask></entry></address>
              </entry></vsys></entry>
          </devices>
        </config>
    """))

    route = result.canonical_ir.routes[0]
    monitor = route.path_monitor
    assert monitor is not None
    assert [item.name for item in monitor.destinations] == ["primary", "secondary"]
    assert monitor.destinations[0].destination_reference == "monitor-ip"
    assert monitor.destinations[0].destination_resolved is True
    assert monitor.destinations[0].resolved_destination == "monitor-ip"
    assert monitor.destinations[1].count == 3
    assert route.source_attributes["pan_bfd_profile"] == "strict-bfd"
    assert result.canonical_ir.pan_high_availability is None


def test_virtual_wire_is_typed_and_zone_owned_with_reverse_interface_evidence():
    result = PANOSSourceParser().extract(dedent("""
        <config><devices><entry name="fw-a">
          <network>
            <interface><ethernet>
              <entry name="ethernet1/1"><layer2/></entry>
              <entry name="ethernet1/2"><layer2/></entry>
            </ethernet></interface>
            <virtual-wire><entry name="transit-vwire">
              <interface1>ethernet1/1</interface1><interface2>ethernet1/2</interface2>
              <tag-allowed>yes</tag-allowed><multicast-firewalling>no</multicast-firewalling>
              <link-state-pass-through>yes</link-state-pass-through>
            </entry></virtual-wire>
          </network>
          <vsys><entry name="vsys1"><zone><entry name="transit">
            <network><virtual-wire><member>transit-vwire</member></virtual-wire></network>
          </entry></zone></entry></vsys>
        </entry></devices></config>
    """))

    vwire = result.canonical_ir.pan_virtual_wires[0]
    assert (vwire.interface1, vwire.interface2) == ("ethernet1/1", "ethernet1/2")
    assert vwire.interface1_resolved is True and vwire.interface2_resolved is True
    assert vwire.tag_allowed is True
    assert vwire.multicast_firewalling is False
    assert vwire.link_state_pass_through is True
    assert vwire.zones == ["transit"]
    interface = next(item for item in result.canonical_ir.interfaces if item.name == "ethernet1/1")
    assert {item["name"] for item in interface.source_attributes["pan_virtual_wires"]} == {"transit-vwire"}


def test_administrator_access_controls_validate_and_resolve_distinct_references():
    result = PANOSSourceParser().extract(dedent("""
        <config>
          <mgt-config>
            <profiles><entry name="custom-admin"><config/></entry></profiles>
            <users><entry name="alice">
              <permissions><role-based><profile>custom-admin</profile></role-based></permissions>
              <authentication-profile>corp-auth</authentication-profile>
              <authentication-sequence>corp-sequence</authentication-sequence>
              <permitted-ip><entry name="192.0.2.10"/><member>not-an-ip</member><member>2001:db8::/64</member></permitted-ip>
              <certificate-authentication><required>yes</required><certificate-profile>admin-cert-profile</certificate-profile></certificate-authentication>
              <phash>redacted</phash><disabled>no</disabled>
            </entry></users>
          </mgt-config>
          <shared>
            <authentication-profile><entry name="corp-auth"><method><local-database/></method></entry></authentication-profile>
            <authentication-sequence><entry name="corp-sequence"><authentication-profiles><member>corp-auth</member></authentication-profiles></entry></authentication-sequence>
            <certificate-profile><entry name="admin-cert-profile"/></certificate-profile>
          </shared>
        </config>
    """))

    admin = result.canonical_ir.administrators[0]
    assert admin.permitted_ips == ["192.0.2.10", "2001:db8::/64"]
    assert admin.invalid_permitted_ips == ["not-an-ip"]
    assert admin.certificate_authentication_required is True
    assert admin.disabled is False
    assert admin.access_profile_resolved is True
    assert admin.authentication_profile_resolved is True
    assert admin.authentication_sequence_resolved is True
    assert admin.certificate_profile_resolved is True
    assert "not-an-ip" in admin.source_attributes["pan_permitted_ips"]


def test_multi_vsys_is_none_without_explicit_flag_and_true_with_explicit_flag():
    absent = PANOSSourceParser().extract("<config><vsys><entry name='vsys1'/></vsys></config>")
    assert absent.canonical_ir.system_settings is None

    present = PANOSSourceParser().extract(
        "<config><devices><entry name='fw-a'><deviceconfig><system><multi-vsys-enabled>yes</multi-vsys-enabled></system></deviceconfig></entry></devices></config>"
    )
    assert present.canonical_ir.system_settings.multi_vsys_enabled is True
    assert present.canonical_ir.pan_device_operational_settings.multi_vsys_enabled is True


def test_panorama_template_stack_feeds_effective_device_network_with_provenance():
    result = PANOSSourceParser().extract(dedent("""
        <config>
          <template><entry name="base-template"><config><devices><entry name="localhost.localdomain">
            <network><interface><ethernet><entry name="ethernet1/1">
              <layer3><ip><entry name="192.0.2.1/24"/></ip></layer3><comment>inherited</comment>
            </entry></ethernet></interface></network>
          </entry></devices></config></entry></template>
          <template-stack><entry name="branch-stack"><templates><member>base-template</member></templates><devices><entry name="SERIAL1"/></devices></entry></template-stack>
          <devices><entry name="SERIAL1"><vsys><entry name="vsys1"/></vsys></entry></devices>
        </config>
    """))

    interface = next(item for item in result.canonical_ir.interfaces
                     if item.name == "ethernet1/1" and item.source_context.startswith("device:SERIAL1"))
    assert interface.ip == "192.0.2.1/24"
    assert interface.source_attributes["pan_template_stack"] == "branch-stack"
    assert any(entry["source"] == "base-template"
               for entries in interface.source_attributes["pan_template_provenance"].values()
               for entry in entries)


def test_pan_os_does_not_fabricate_fortigate_alg_nat_or_ngfw_state():
    result = PANOSSourceParser().extract(dedent("""
        <config><vsys><entry name="vsys1"><rulebase><security><rules><entry name="app-rule">
          <from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <source-user><member>DOMAIN\\alice</member></source-user>
          <application><member>web-browsing</member></application>
          <service><member>application-default</member></service>
          <category><member>adult</member></category>
          <profile-setting><group><member>strict-profiles</member></group></profile-setting>
          <action>allow</action>
        </entry></rules></security></rulebase></entry></vsys></config>
    """))

    policy = result.canonical_ir.policies[0]
    assert result.canonical_ir.session_helpers == []
    assert result.canonical_ir.central_snat_rules == []
    assert all(context.ngfw_mode is None for context in result.canonical_ir.execution_contexts)
    assert policy.applications == ["web-browsing"]
    assert policy.service == ["application-default"]
    assert policy.source_users == [r"DOMAIN\alice"]
    assert policy.url_categories == ["adult"]


def test_schema_1_53_migrates_to_current_after_phase6_11_fields():
    assert migrate_ir_payload({"schema_version": "1.53"})["schema_version"] == "1.59"
