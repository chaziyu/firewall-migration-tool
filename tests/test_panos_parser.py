import pytest
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import AddressType, PolicyAction
from tests.fixture_paths import PALO_ALTO_FIXTURE

def test_panos_source_parser_from_example():
    assert PALO_ALTO_FIXTURE.exists()

    with open(PALO_ALTO_FIXTURE, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("palo_alto")
    ir = parser.parse(content)

    assert ir.metadata.source_vendor == "palo_alto"
    assert len(ir.zones) >= 1
    assert len(ir.addresses) >= 1
    assert len(ir.policies) >= 1

def test_panos_source_parser_snippet():
    xml_snippet = """
    <config version="10.2.0">
      <mgt-config>
        <system>
          <hostname>DC-PAN-FW01</hostname>
        </system>
      </mgt-config>
      <devices>
        <entry name="localhost.localdomain">
          <vsys>
            <entry name="vsys1">
              <zone>
                <entry name="trust">
                  <network><layer3><member>ethernet1/1</member></layer3></network>
                </entry>
                <entry name="untrust">
                  <network><layer3><member>ethernet1/2</member></layer3></network>
                </entry>
              </zone>
              <address>
                <entry name="Server_Web">
                  <ip-netmask>10.10.10.50/32</ip-netmask>
                  <description>Production Web Server</description>
                </entry>
                <entry name="Net_LAN">
                  <ip-netmask>10.10.0.0/16</ip-netmask>
                </entry>
                <entry name="Pool_DHCP">
                  <ip-range>192.168.1.100-192.168.1.200</ip-range>
                </entry>
                <entry name="FQDN_API">
                  <fqdn>api.gateway.io</fqdn>
                </entry>
              </address>
              <address-group>
                <entry name="Grp_Internal">
                  <static>
                    <member>Server_Web</member>
                    <member>Net_LAN</member>
                  </static>
                </entry>
              </address-group>
              <service>
                <entry name="svc_custom_8443">
                  <protocol>
                    <tcp><port>8443</port></tcp>
                  </protocol>
                </entry>
              </service>
              <service-group>
                <entry name="Grp_Custom_Svcs">
                  <members>
                    <member>svc_custom_8443</member>
                  </members>
                </entry>
              </service-group>
              <rulebase>
                <security>
                  <rules>
                    <entry name="Allow_Web_Outbound">
                      <from><member>trust</member></from>
                      <to><member>untrust</member></to>
                      <source><member>Grp_Internal</member></source>
                      <destination><member>any</member></destination>
                      <application><member>any</member></application>
                      <service><member>svc_custom_8443</member></service>
                      <action>allow</action>
                    </entry>
                  </rules>
                </security>
              </rulebase>
            </entry>
          </vsys>
        </entry>
      </devices>
    </config>
    """
    parser = PANOSSourceParser()
    ir = parser.parse(xml_snippet)

    assert ir.metadata.hostname == "DC-PAN-FW01"
    assert ir.metadata.source_vendor == "palo_alto"
    assert len(ir.zones) == 2
    assert len(ir.addresses) == 4

    web_addr = next(a for a in ir.addresses if a.name == "Server_Web")
    assert web_addr.type == AddressType.HOST
    assert web_addr.value == "10.10.10.50/32"

    range_addr = next(a for a in ir.addresses if a.name == "Pool_DHCP")
    assert range_addr.type == AddressType.RANGE

    assert len(ir.address_groups) == 1
    assert len(ir.services) == 1
    assert len(ir.service_groups) == 1
    assert len(ir.policies) == 1
    assert ir.policies[0].name == "Allow_Web_Outbound"
    assert ir.policies[0].action == PolicyAction.ALLOW
