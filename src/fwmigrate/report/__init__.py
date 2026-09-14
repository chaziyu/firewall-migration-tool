from fwmigrate.report import excel_exporter as _excel_exporter
from fwmigrate.report.excel_effective_order import EffectiveOrderIRExcelExporter

ExcelExportUnavailableError = _excel_exporter.ExcelExportUnavailableError
XLSX_MIMETYPE = _excel_exporter.XLSX_MIMETYPE

# Preserve the existing import surface. Callers that import IRExcelExporter from
# either fwmigrate.report or fwmigrate.report.excel_exporter receive the same
# source-vendor-aware implementation without changing web, parser, IR, or
# generator code.
_excel_exporter.IRExcelExporter = EffectiveOrderIRExcelExporter
IRExcelExporter = EffectiveOrderIRExcelExporter

__all__ = ["ExcelExportUnavailableError", "IRExcelExporter", "XLSX_MIMETYPE"]
