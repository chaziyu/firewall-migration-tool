from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _section(extraction, path):
    return next(section for section in extraction.source_sections if section.path == path)


def test_withheld_security_rule_is_counted_without_silent_loss():
    xml = """
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="missing-source">
            <from><member>trust</member></from>
            <to><member>untrust</member></to>
            <destination><member>any</member></destination>
            <application><member>any</member></application>
            <service><member>application-default</member></service>
            <action>allow</action>
          </entry>
        </rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>
    """
    extraction = PANOSSourceParser().extract(xml)

    assert extraction.canonical_ir.policies == []
    records = [item for item in extraction.inventory_items if item.domain == "policies"]
    assert len(records) == 1
    assert records[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert records[0].requires_manual_review is True

    section = _section(extraction, "rulebase/security/rules")
    assert section.object_count_source == 1
    assert section.object_count_parsed == 0
    assert section.object_count_normalized == 0
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_withheld_nat_rule_is_counted_without_silent_loss():
    xml = """
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><nat><rules>
          <entry name="missing-service">
            <from><member>trust</member></from>
            <to><member>untrust</member></to>
            <source><member>any</member></source>
            <destination><member>any</member></destination>
            <source-translation>
              <dynamic-ip-and-port>
                <translated-address><member>203.0.113.10</member></translated-address>
              </dynamic-ip-and-port>
            </source-translation>
          </entry>
        </rules></nat></rulebase>
      </entry></vsys></entry></devices>
    </config>
    """
    extraction = PANOSSourceParser().extract(xml)

    assert extraction.canonical_ir.nat_rules == []
    records = [item for item in extraction.inventory_items if item.domain == "nat"]
    assert len(records) == 1
    assert records[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert records[0].requires_manual_review is True

    section = _section(extraction, "rulebase/nat/rules")
    assert section.object_count_source == 1
    assert section.object_count_parsed == 0
    assert section.object_count_normalized == 0
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_out_of_range_static_route_is_counted_as_parse_error():
    xml = """
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain">
        <network><virtual-router><entry name="default">
          <routing-table><ip><static-route>
            <entry name="bad-metric">
              <destination>10.20.0.0/16</destination>
              <nexthop><ip-address>192.0.2.1</ip-address></nexthop>
              <metric>65536</metric>
              <admin-dist>10</admin-dist>
            </entry>
          </static-route></ip></routing-table>
        </entry></virtual-router></network>
        <vsys><entry name="vsys1"/></vsys>
      </entry></devices>
    </config>
    """
    extraction = PANOSSourceParser().extract(xml)

    assert extraction.canonical_ir.routes == []
    records = [item for item in extraction.inventory_items if item.domain == "routes"]
    assert len(records) == 1
    assert records[0].status == ExtractionStatus.PARSE_ERROR
    assert records[0].requires_manual_review is True
    assert records[0].source_attributes["pan_metric_source"] == "65536"

    section = _section(extraction, "network/routing-instances/ipv4/static-route")
    assert section.object_count_source == 1
    assert section.object_count_parsed == 0
    assert section.object_count_normalized == 0
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED
