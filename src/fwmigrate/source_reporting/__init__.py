"""Vendor-native source analysis and reporting contracts."""

from fwmigrate.source_reporting.contracts import SourceReporter
from fwmigrate.source_reporting.registry import (
    SourceReportRegistrationError,
    SourceReportRegistry,
    source_reporters,
)
from fwmigrate.source_reporting.excel_utils import (
    configure_table_view,
    safe_cell_value,
    safe_source_cell,
    set_column_widths,
)
from fwmigrate.source_reporting.metrics import (
    ExcelExportMetrics,
    SourceReportMetrics,
    SourceReportStageMetric,
)
from fwmigrate.source_reporting.options import (
    ExcelExportProfile,
    ExcelExportUnavailableError,
    XLSX_MIMETYPE,
)
from fwmigrate.source_reporting.web_report import (
    REPORT_SECTIONS,
    empty_report_sections,
    normalize_web_report,
    validate_web_report_payload,
)

__all__ = [
    "SourceReportRegistrationError",
    "SourceReportRegistry",
    "SourceReporter",
    "SourceReportMetrics",
    "SourceReportStageMetric",
    "ExcelExportMetrics",
    "ExcelExportProfile",
    "ExcelExportUnavailableError",
    "XLSX_MIMETYPE",
    "source_reporters",
    "configure_table_view",
    "safe_cell_value",
    "safe_source_cell",
    "set_column_widths",
    "REPORT_SECTIONS",
    "empty_report_sections",
    "normalize_web_report",
    "validate_web_report_payload",
]
