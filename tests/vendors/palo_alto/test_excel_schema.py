from fwmigrate.vendors.palo_alto.export.excel_schema import (
    ACTIVE_SHEET_ORDER,
    SHEET_HEADERS,
    SHEET_IMPLEMENTATION_STATUS,
)


def test_active_sheets_have_declared_headers_and_status():
    assert set(ACTIVE_SHEET_ORDER) <= set(SHEET_HEADERS)
    assert (set(ACTIVE_SHEET_ORDER) - {"Summary"}) <= set(SHEET_IMPLEMENTATION_STATUS)
    assert all(SHEET_HEADERS[name] for name in ACTIVE_SHEET_ORDER if name != "Summary")
