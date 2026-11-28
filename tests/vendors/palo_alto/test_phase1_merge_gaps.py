from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_server_profile_compat_paths_extract_to_typed_collections():
    xml = """<config><shared>
      <server-profile>
        <syslog><entry name='sys-1'><server><entry name='s1'><server>192.0.2.10</server><port>514</port></entry></server></entry></syslog>
        <email><entry name='mail-1'><server><entry name='m1'><gateway>192.0.2.20</gateway></entry></server></entry></email>
        <snmptrap><entry name='snmp-1'><version><v2c><server><entry name='t1'><manager>192.0.2.30</manager></entry></server></v2c></version></entry></snmptrap>
        <http><entry name='http-1'><server><entry name='h1'><address>192.0.2.40</address></entry></server></entry></http>
      </server-profile>
    </shared></config>"""
    analysis = PaloAltoSourceReporter().analyze_source(xml)
    config = analysis.config
    assert [x.name for x in config.syslog_server_profiles] == ["sys-1"]
    assert [x.name for x in config.email_server_profiles] == ["mail-1"]
    assert [x.name for x in config.snmptrap_server_profiles] == ["snmp-1"]
    assert [x.name for x in config.http_server_profiles] == ["http-1"]
    assert analysis.accounting.source_domains["syslog_server_profile_compat"] == 1
    assert analysis.accounting.extracted_domains["syslog_server_profile_compat"] == 1


def test_external_zone_and_sctp_service_are_extracted():
    xml = """<config><shared>
      <zone><entry name='ext-zone'><network><external><member>ethernet1/1</member></external></network></entry></zone>
      <service><entry name='diam'><protocol><sctp><port>3868</port><source-port>1024-65535</source-port></sctp></protocol></entry></service>
    </shared></config>"""
    config = build_panos_config(xml)
    zone = config.zones[0]
    assert zone.network_type == "external"
    assert zone.members == ["ethernet1/1"]
    assert {"network_type", "members"} <= zone.explicit_fields

    svc = config.services[0]
    assert svc.sctp is not None
    assert svc.sctp.port == "3868"
    assert svc.sctp.source_port == "1024-65535"
    assert "sctp" in svc.explicit_fields


def test_qos_action_class_and_dos_nested_from_to_and_interface_mgmt_fallback():
    xml = """<config><devices><entry name='fw'>
      <network>
        <profiles><interface-management-profile><entry name='mgmt-https'><https>yes</https></entry></interface-management-profile></profiles>
        <interface>
          <ethernet>
            <entry name='ethernet1/1'>
              <link-state>up</link-state>
              <layer3>
                <interface-management-profile>mgmt-https</interface-management-profile>
                <ip><entry name='198.51.100.1/24'/></ip>
                <units><entry name='ethernet1/1.10'><ip><entry name='10.10.10.1/24'/></ip></entry></units>
              </layer3>
            </entry>
            <entry name='ethernet1/2'><interface-management-profile>mgmt-https</interface-management-profile></entry>
          </ethernet>
        </interface>
      </network>
      <vsys><entry name='vsys1'>
        <zone><entry name='untrust'><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
        <rulebase>
          <qos><rules><entry name='qos-action'><action><class>5</class></action></entry></rules></qos>
          <dos><rules><entry name='dos-nested'>
            <from><zone><member>untrust</member></zone><interface><member>ethernet1/1</member></interface></from>
            <to><interface><member>ethernet1/2</member></interface></to>
          </entry></rules></dos>
          <nat><rules><entry name='disabled-nat'><disabled>yes</disabled><from><member>untrust</member></from><to><member>untrust</member></to></entry></rules></nat>
        </rulebase>
      </entry></vsys>
    </entry></devices></config>"""
    config = build_panos_config(xml)
    derived = build_derived_views(config)

    assert config.qos_rules[0].qos_class == "5"
    assert "qos_class" in config.qos_rules[0].explicit_fields

    dos = config.dos_rules[0]
    assert dos.from_zones == ["untrust"]
    assert dos.from_interfaces == ["ethernet1/1"]
    assert dos.to_interfaces == ["ethernet1/2"]
    assert dos.to_zones is None
    assert "to_zones" not in dos.explicit_fields

    eth2 = next(i for i in config.interfaces if i.name == "ethernet1/2")
    assert eth2.management_profile == "mgmt-https"
    assert "management_profile" in eth2.explicit_fields

    topo = {item.interface: item for item in derived.interface_topology}
    assert topo["ethernet1/1"].ipv4_addresses == ("198.51.100.1/24",)
    assert topo["ethernet1/1"].link_state == "up"
    assert topo["ethernet1/1"].management_profile == "mgmt-https"
    assert topo["ethernet1/1.10"].ipv4_addresses == ("10.10.10.1/24",)
    assert topo["ethernet1/1.10"].link_state is None
    assert topo["ethernet1/1.10"].parent_link_state == "up"

    assert derived.nat[0].disabled == "yes"
