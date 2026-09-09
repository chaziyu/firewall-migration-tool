from io import BytesIO

import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


FORTIGATE_CONFIG = """
config system global
    set hostname "FG-TEST"
end

config system session-helper
    edit 1
        set name pptp
        set protocol 6
        set port 1723
    next
    edit 9
        set name ftp
        set protocol 6
        set port 2121
    next
    edit 50
        set name custom-app
        set protocol 6
        set port 9000
    next
end
"""


def test_session_helper_parser():
    fg = parse_fortigate_config(FORTIGATE_CONFIG)

    assert len(fg.session_helpers) == 3
    assert fg.session_helpers[0].id == 1
    assert fg.session_helpers[0].name == "pptp"
    assert fg.session_helpers[0].protocol == 6
    assert fg.session_helpers[0].port == 1723


def test_session_helper_classification():
    ir = FGToIRTransformer(parse_fortigate_config(FORTIGATE_CONFIG)).transform()
    by_id = {item.source_id: item for item in ir.session_helpers}

    assert len(ir.session_helpers) == 3
    assert by_id[1].classification == "DEFAULT"
    assert by_id[1].requires_manual_review is False
    assert by_id[9].classification == "CUSTOMIZED"
    assert by_id[9].requires_manual_review is True
    assert by_id[50].classification == "CUSTOM"
    assert by_id[50].requires_manual_review is True


def test_session_helpers_excel():
    openpyxl = pytest.importorskip("openpyxl")
    ir = FGToIRTransformer(parse_fortigate_config(FORTIGATE_CONFIG)).transform()
    workbook_bytes = IRExcelExporter(ir).generate()
    workbook = openpyxl.load_workbook(BytesIO(workbook_bytes))

    assert "Session Helpers" in workbook.sheetnames
    sheet = workbook["Session Helpers"]
    headers = [cell.value for cell in sheet[3]]
    assert "Classification" in headers
    assert "Manual Review" in headers

    flattened = [
        value
        for row in sheet.iter_rows(min_row=4, values_only=True)
        for value in row
    ]
    assert "pptp" in flattened
    assert "DEFAULT" in flattened
    assert "CUSTOMIZED" in flattened
    assert "CUSTOM" in flattened
