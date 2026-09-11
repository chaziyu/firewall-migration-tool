import io

from openpyxl import load_workbook

from fwmigrate.ir.core import IRNATRule, IRRoute
from fwmigrate.ir.enums import IRRouteNextHopType, NATTranslationMode, NATType
from fwmigrate.parsers.palo_alto import PANOSSourceParser
from fwmigrate.report.excel_exporter import IRExcelExporter


def _nat_config(rules: str) -> str:
    return f"""<config><devices><entry name='fw'><vsys><entry name='vsys1'>
      <rulebase><nat><rules>{rules}</rules></nat></rulebase>
    </entry></vsys></entry></devices></config>"""


def _nat_match(name: str, translation: str = "") -> str:
    return f"""<entry name='{name}'><from><member>trust</member></from>
      <to><member>untrust</member></to><source><member>any</member></source>
      <destination><member>any</member></destination><service>any</service>{translation}</entry>"""


def test_new_ir_nat_and_route_fields_are_serializable():
    nat = IRNATRule(
        name="identity", type=NATType.SOURCE,
        source_translation_mode=NATTranslationMode.NONE,
        source_translation_bidirectional=True,
    )
    route = IRRoute(name="logical", next_hop_type=IRRouteNextHopType.NEXT_LR)

    assert nat.model_dump(mode="json")["source_translation_mode"] == "none"
    assert nat.model_dump(mode="json")["source_translation_bidirectional"] is True
    assert route.model_dump(mode="json")["next_hop_type"] == "next-lr"


def test_pan_nat_preserves_order_identity_dynamic_ip_and_static_direction():
    result = PANOSSourceParser().extract(_nat_config("".join([
        _nat_match("identity"),
        _nat_match("dynamic", "<source-translation><dynamic-ip><translated-address><member>203.0.113.10</member></translated-address></dynamic-ip></source-translation>"),
        _nat_match("static", "<source-translation><static-ip><translated-address>203.0.113.20</translated-address><bi-directional>yes</bi-directional></static-ip></source-translation>"),
    ])))
    rules = result.canonical_ir.nat_rules

    assert [rule.name for rule in rules] == ["identity", "dynamic", "static"]
    assert rules[0].source_translation_mode == NATTranslationMode.NONE
    assert rules[1].source_translation_mode == NATTranslationMode.DYNAMIC_IP
    assert rules[2].source_translation_bidirectional is True


def test_default_override_and_pbf_are_canonical_and_exported():
    xml = """<config><devices><entry name='fw'><network>
      <interface><ethernet><entry name='ethernet1/1'/></ethernet></interface>
    </network><vsys><entry name='vsys1'>
      <zone><entry name='trust'/></zone>
      <rulebase><default-security-rules><rules><entry name='interzone-default'>
        <action>deny</action><disabled>yes</disabled><log-end>yes</log-end>
      </entry></rules></default-security-rules>
      <pbf><rules><entry name='pbf'><from><zone><member>trust</member></zone></from>
        <action><forward><egress-interface>ethernet1/1</egress-interface></forward></action>
      </entry></rules></pbf></rulebase>
    </entry></vsys></entry></devices></config>"""
    result = PANOSSourceParser().extract(xml)
    ir = result.canonical_ir
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))

    assert ir.default_security_rules[0].action.value == "deny"
    assert ir.default_security_rules[0].disabled is True
    assert ir.pbf_rules[0].migration_status == "NORMALIZED"
    assert "Default Security Rules" in workbook.sheetnames
    nat_headers = {cell.value for cell in workbook["NAT Rules"][3]}
    assert {"Destination Translation Mode", "Static NAT Bi-directional"} <= nat_headers
