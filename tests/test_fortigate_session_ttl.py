from io import BytesIO

import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


FORTIGATE_CONFIG = """
config system global
    set hostname "FG-TEST"
end

config system session-ttl
    config port
        edit 1
            set protocol 6
            set timeout 3600
            set start-port 3389
            set end-port 3389
        next
        edit 2
            set protocol 17
            set timeout 3600
            set start-port 3389
            set end-port 3389
        next
    end
end
"""


def test_session_ttl_parser():
    fg = parse_fortigate_config(FORTIGATE_CONFIG)

    assert len(fg.session_ttl_overrides) == 2

    tcp = fg.session_ttl_overrides[0]

    assert tcp.id == 1
    assert tcp.protocol == 6
    assert tcp.timeout == 3600
    assert tcp.start_port == 3389
    assert tcp.end_port == 3389


def test_session_ttl_transformer():
    fg = parse_fortigate_config(FORTIGATE_CONFIG)

    ir = FGToIRTransformer(fg).transform()

    assert len(ir.session_ttl_overrides) == 2

    tcp = ir.session_ttl_overrides[0]
    udp = ir.session_ttl_overrides[1]

    assert tcp.protocol_name == "TCP"
    assert tcp.protocol_number == 6
    assert tcp.start_port == 3389
    assert tcp.end_port == 3389
    assert tcp.timeout_seconds == 3600
    assert tcp.migration_status == "EXTRACT_ONLY"
    assert tcp.requires_manual_review is True

    assert udp.protocol_name == "UDP"
    assert udp.protocol_number == 17


def test_session_ttl_excel():
    openpyxl = pytest.importorskip("openpyxl")

    fg = parse_fortigate_config(FORTIGATE_CONFIG)
    ir = FGToIRTransformer(fg).transform()
    workbook_bytes = IRExcelExporter(ir).generate()
    workbook = openpyxl.load_workbook(BytesIO(workbook_bytes))

    assert "Session TTL Overrides" in workbook.sheetnames

    sheet = workbook["Session TTL Overrides"]
    headers = [cell.value for cell in sheet[3]]

    assert "Protocol" in headers
    assert "Timeout (Seconds)" in headers
    assert "Manual Review" in headers

    assert sheet["B4"].value == "TCP"
    assert sheet["D4"].value == 3389
    assert sheet["E4"].value == 3389
    assert sheet["F4"].value == 3600
    assert sheet["G4"].value == "EXTRACT_ONLY"
    assert sheet["H4"].value == "Yes"

    assert sheet["B5"].value == "UDP"
