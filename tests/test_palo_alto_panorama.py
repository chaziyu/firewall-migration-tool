import pytest
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser

def test_panorama_device_group_parsing():
    xml_content = """<?xml version="1.0"?>
    <config version="10.0.0">
      <readonly>
        <devices>
          <entry name="localhost.localdomain">
            <device-group>
              <entry name="Branch_Offices">
                <address>
                  <entry name="Branch_Net">
                    <ip-netmask>192.168.100.0/24</ip-netmask>
                  </entry>
                </address>
                <pre-rulebase>
                  <security>
                    <rules>
                      <entry name="PreRule1">
                        <from><member>any</member></from>
                        <to><member>any</member></to>
                        <source><member>Branch_Net</member></source>
                        <destination><member>any</member></destination>
                        <application><member>any</member></application>
                        <service><member>any</member></service>
                        <action>allow</action>
                      </entry>
                    </rules>
                  </security>
                </pre-rulebase>
              </entry>
            </device-group>
          </entry>
        </devices>
      </readonly>
    </config>
    """
    parser = PANOSSourceParser()
    ir = parser.parse(xml_content)
    assert len(ir.addresses) == 1
    assert ir.addresses[0].name == "Branch_Net"
    assert len(ir.policies) == 1
    assert ir.policies[0].name == "PreRule1"
