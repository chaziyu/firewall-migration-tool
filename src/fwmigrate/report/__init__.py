from fwmigrate.report import excel_exporter as _excel_exporter

# Register sheets contributed by layered exporters before those exporters snapshot
# the base workbook order.
_PREMATCH_SHEET = "NGFW Pre-Match Policies"
_ADDRESS6_TEMPLATE_SHEET = "IPv6 Address Templates"
_base_order = list(_excel_exporter.IRExcelExporter.SHEET_ORDER)
if _PREMATCH_SHEET not in _base_order:
    insert_at = (
        _base_order.index("NGFW Security Policies")
        if "NGFW Security Policies" in _base_order
        else _base_order.index("Policies") + 1
    )
    _base_order.insert(insert_at, _PREMATCH_SHEET)
if _ADDRESS6_TEMPLATE_SHEET not in _base_order:
    insert_at = (
        _base_order.index("Address Groups")
        if "Address Groups" in _base_order
        else len(_base_order)
    )
    _base_order.insert(insert_at, _ADDRESS6_TEMPLATE_SHEET)
_excel_exporter.IRExcelExporter.SHEET_ORDER = tuple(_base_order)

from fwmigrate.report.excel_effective_order import EffectiveOrderIRExcelExporter
from fwmigrate.report.fortigate_semantics_excel import FortiGateSemanticsExcelExporter
from fwmigrate.report.excel_readability import ReadableFortiGateExcelExporter
from fwmigrate.report.fortigate_address_schedule_excel import (
    FortiGateAddressScheduleExcelExporter,
)
from fwmigrate.report.excel_optimized import SinglePassIRExcelExporter
from fwmigrate.report.nat_audit_excel import NATAuditIRExcelExporter
from fwmigrate.report.excel_options import ExcelExportOptions, ExcelExportProfile

ExcelExportUnavailableError = _excel_exporter.ExcelExportUnavailableError
XLSX_MIMETYPE = _excel_exporter.XLSX_MIMETYPE

# Preserve the existing import surface while routing generation through the
# single-pass workbook lifecycle plus the final NAT audit visibility layer.
_excel_exporter.IRExcelExporter = NATAuditIRExcelExporter
IRExcelExporter = NATAuditIRExcelExporter

__all__ = [
    "ExcelExportOptions",
    "ExcelExportProfile",
    "ExcelExportUnavailableError",
    "IRExcelExporter",
    "XLSX_MIMETYPE",
]
