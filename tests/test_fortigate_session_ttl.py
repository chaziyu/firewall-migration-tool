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

SESSION_TTL_GAPS_CONFIG = """
config system session-ttl
    set default 900
    config port
        edit 1
            set protocol 6
            set start-port 443
            set end-port 443
            set timeout 300
        next
        edit 2
            set protocol 17
            set start-port 53
            set end-port 53
            set timeout never
            set refresh-direction outgoing
        next
    end
end
"""

SESSION_TTL_NEVER_CONFIG = """
config system session-ttl
    set default never
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
    assert "Timeout" in headers
    assert "Refresh Direction" in headers
    assert "Manual Review" in headers

    assert sheet["B4"].value == "TCP"
    assert sheet["D4"].value == 3389
    assert sheet["E4"].value == 3389
    assert sheet["F4"].value == 3600
    assert sheet["H4"].value == "EXTRACT_ONLY"
    assert sheet["I4"].value == "Yes"

    assert sheet["B5"].value == "UDP"


def test_session_ttl_numeric_never_and_refresh_direction():
    openpyxl = pytest.importorskip("openpyxl")
    fg = parse_fortigate_config(SESSION_TTL_GAPS_CONFIG)
    ir = FGToIRTransformer(fg).transform()

    assert fg.session_ttl_settings.default_timeout == 900
    assert fg.session_ttl_settings.default_never is False
    assert ir.session_ttl_settings.default_timeout_seconds == 900
    assert ir.session_ttl_settings.default_never is False

    first, second = ir.session_ttl_overrides
    assert first.timeout_seconds == 300
    assert first.timeout_never is False
    assert second.timeout_seconds is None
    assert second.timeout_never is True
    assert second.refresh_direction == "outgoing"
    assert "refresh_direction" not in second.source_attributes

    workbook = openpyxl.load_workbook(
        BytesIO(IRExcelExporter(ir).generate())
    )
    settings = workbook["Session TTL Settings"]
    settings_headers = {cell.value: cell.column for cell in settings[3]}
    assert settings.cell(4, settings_headers["Default TTL"]).value == 900

    overrides = workbook["Session TTL Overrides"]
    headers = {cell.value: cell.column for cell in overrides[3]}
    assert overrides.cell(5, headers["Timeout"]).value == "never"
    assert overrides.cell(5, headers["Refresh Direction"]).value == "outgoing"


def test_session_ttl_never_global_default_is_not_unparsed():
    openpyxl = pytest.importorskip("openpyxl")
    fg = parse_fortigate_config(SESSION_TTL_NEVER_CONFIG)
    ir = FGToIRTransformer(fg).transform()

    assert fg.session_ttl_settings.default_timeout is None
    assert fg.session_ttl_settings.default_never is True
    assert "unparsed_default" not in fg.session_ttl_settings.extra_settings
    assert ir.session_ttl_settings.default_timeout_seconds is None
    assert ir.session_ttl_settings.default_never is True

    workbook = openpyxl.load_workbook(BytesIO(IRExcelExporter(ir).generate()))
    sheet = workbook["Session TTL Settings"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    assert sheet.cell(4, headers["Default TTL"]).value == "never"
