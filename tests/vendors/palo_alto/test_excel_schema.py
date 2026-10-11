from fwmigrate.vendors.palo_alto.export.excel_rows import ROW_BUILDERS
from fwmigrate.vendors.palo_alto.export.excel_schema import (
    SHEET_ORDER,
    SHEET_HEADERS,
)


def test_declared_sheets_have_headers_and_row_builders():
    assert set(SHEET_ORDER) <= set(SHEET_HEADERS)
    assert set(SHEET_ORDER) - {"Summary"} <= set(ROW_BUILDERS)
    assert all(SHEET_HEADERS[name] for name in SHEET_ORDER if name != "Summary")
