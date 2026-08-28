import pytest
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser

# Phase 00: Safety regression baseline
# These tests are EXPECTED TO FAIL initially until unsafe defaults are removed in Phase 02.
# We do not assert that the result is `["any"]` or `ALLOW`; we assert that it is NOT.

def test_missing_policy_fields_do_not_broaden_to_any():
    xml_content = """<?xml version="1.0"?>
    <config version="10.0.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="Rule1">
            <action>allow</action>
            <!-- Missing from, to, source, destination, application, service -->
          </entry>
        </rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>
    """
    parser = PANOSSourceParser()
    ir = parser.parse(xml_content)
    assert len(ir.policies) == 0
    extraction = parser.extract(xml_content)
    assert len(extraction.inventory_items) >= 1
    assert any("missing required fields" in item.notes[0].lower() for item in extraction.inventory_items)

def test_missing_action_does_not_broaden_to_allow():
    xml_content = """<?xml version="1.0"?>
    <config version="10.0.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="Rule1">
            <from><member>trust</member></from>
            <to><member>untrust</member></to>
            <source><member>10.0.0.1</member></source>
            <destination><member>8.8.8.8</member></destination>
            <service><member>application-default</member></service>
            <!-- Missing action -->
          </entry>
        </rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>
    """
    parser = PANOSSourceParser()
    ir = parser.parse(xml_content)
    assert len(ir.policies) == 0
    extraction = parser.extract(xml_content)
    assert len(extraction.inventory_items) >= 1
    assert any("missing required action" in item.notes[0].lower() for item in extraction.inventory_items)

def test_missing_route_destination_does_not_become_default_route():
    xml_content = """<?xml version="1.0"?>
    <config version="10.0.0">
      <devices><entry name="localhost.localdomain"><network><virtual-router>
        <entry name="default">
          <routing-table><ip><static-route>
            <entry name="bad-route">
              <nexthop><ip-address>192.168.1.1</ip-address></nexthop>
              <!-- Missing destination -->
            </entry>
          </static-route></ip></routing-table>
        </entry>
      </virtual-router></network></entry></devices>
    </config>
    """
    parser = PANOSSourceParser()
    ir = parser.parse(xml_content)
    assert len(ir.routes) == 0
    extraction = parser.extract(xml_content)
    assert len(extraction.inventory_items) >= 1
    assert any("missing required destination" in item.notes[0] for item in extraction.inventory_items)
