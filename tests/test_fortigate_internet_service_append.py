from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


def test_append_direct_section_has_no_invented_id_and_preserves_unknown_settings():
    fg = parse_fortigate_config("""
config firewall internet-service-append
    set addr-mode ipv4
    set append-port 8080
    set match-port 80
    set future-option retained
end
""")
    item = fg.internet_service_appends[0]

    assert (item.addr_mode, item.append_port, item.match_port) == ("ipv4", 8080, 80)
    assert item.extra_settings == {"future_option": "retained"}
    assert "id" not in item.model_dump()

    ir_item = FGToIRTransformer(fg).transform().internet_service_appends[0]
    assert (ir_item.addr_mode, ir_item.append_port, ir_item.match_port) == ("ipv4", 8080, 80)
    assert "source_id" not in ir_item.model_dump()
    assert ir_item.source_attributes == {"future_option": "retained"}

    workbook = load_workbook(BytesIO(IRExcelExporter(FGToIRTransformer(fg).transform()).generate()))
    headers = [cell.value for cell in workbook["IS Appends"][3]]
    assert "Internet Service ID" not in headers


def test_append_invalid_port_is_retained_for_manual_review():
    result = extract_fortigate_config("""
config firewall internet-service-append
    set append-port 70000
    set match-port 80
end
""")
    item = result.canonical_ir.internet_service_appends[0]

    assert item.append_port is None
    assert item.source_attributes["invalid_fields"]["append_port"] == "70000"
