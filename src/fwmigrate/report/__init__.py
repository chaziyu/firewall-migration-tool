from fwmigrate.report import excel_exporter as _excel_exporter

# Register the dedicated FortiGate pre-match sheet before the vendor-aware
# exporter snapshots the base workbook order.
_PREMATCH_SHEET = "NGFW Pre-Match Policies"
_base_order = list(_excel_exporter.IRExcelExporter.SHEET_ORDER)
if _PREMATCH_SHEET not in _base_order:
    insert_at = (
        _base_order.index("NGFW Security Policies")
        if "NGFW Security Policies" in _base_order
        else _base_order.index("Policies") + 1
    )
    _base_order.insert(insert_at, _PREMATCH_SHEET)
    _excel_exporter.IRExcelExporter.SHEET_ORDER = tuple(_base_order)

from fwmigrate.report.excel_vendor_visibility import VendorAwareIRExcelExporter
from fwmigrate.report.fortigate_semantics_excel import (
    FortiGateSemanticsExcelExporter,
)

ExcelExportUnavailableError = _excel_exporter.ExcelExportUnavailableError
XLSX_MIMETYPE = _excel_exporter.XLSX_MIMETYPE

# Preserve the existing import surface. Callers that import IRExcelExporter from
# either fwmigrate.report or fwmigrate.report.excel_exporter receive the same
# vendor-aware implementation with FortiGate semantic corrections.
_excel_exporter.IRExcelExporter = FortiGateSemanticsExcelExporter
IRExcelExporter = FortiGateSemanticsExcelExporter

__all__ = ["ExcelExportUnavailableError", "IRExcelExporter", "XLSX_MIMETYPE"]
