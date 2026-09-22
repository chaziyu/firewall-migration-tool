from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.vendors.juniper_srx import JuniperSRXParser
from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source
from fwmigrate.vendors.juniper_srx.export.excel import export_juniper_excel


def test_source_extraction_preserves_contexts_groups_and_activation():
    content = """
set system host-name edge
set groups base system time-zone UTC
set apply-groups base
set logical-systems LS1 interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
deactivate logical-systems LS1 interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
activate logical-systems LS1 interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
"""
    parser = JuniperSRXParser(content)
    config = parser.extract_source()

    assert "LS1" in config.contexts
    assert "base" in config.configuration_groups
    assert config.hostname == "edge"
    assert parser.source_format == "junos_display_set"
    assert parser.commands


def test_source_report_and_excel_keep_junos_contexts_and_redact_secrets():
    result = extract_juniper_source(
        "set system host-name edge\nset security ike gateway gw pre-shared-key super-secret\n"
    )
    assert any(item.source_path == "system" for item in result.inventory_items)
    output = BytesIO()
    export_juniper_excel(result, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)
    text = "\n".join(str(cell.value) for sheet in workbook.worksheets for row in sheet.iter_rows() for cell in row)
    assert "super-secret" not in text
