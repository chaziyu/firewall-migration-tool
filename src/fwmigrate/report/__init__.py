from fwmigrate.report import excel_exporter as _excel_exporter

# Register the FortiGate pre-match sheet before the layered Excel exporters
# snapshot the base workbook order.
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

from fwmigrate.report.excel_effective_order import EffectiveOrderIRExcelExporter
from fwmigrate.report.fortigate_semantics_excel import FortiGateSemanticsExcelExporter
from fwmigrate.report.excel_readability import ReadableFortiGateExcelExporter
from fwmigrate.report.fortigate_address_schedule_excel import (
    FortiGateAddressScheduleExcelExporter,
)

ExcelExportUnavailableError = _excel_exporter.ExcelExportUnavailableError
XLSX_MIMETYPE = _excel_exporter.XLSX_MIMETYPE

# Preserve the existing import surface. The correction layer subclasses the
# current readability/FortiGate exporter so presentation and semantics compose.
_excel_exporter.IRExcelExporter = FortiGateAddressScheduleExcelExporter
IRExcelExporter = FortiGateAddressScheduleExcelExporter

__all__ = ["ExcelExportUnavailableError", "IRExcelExporter", "XLSX_MIMETYPE"]
