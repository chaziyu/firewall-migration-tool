"""Vendor-native source analysis and reporting contracts."""

from fwmigrate.source_reporting.contracts import SourceReporter
from fwmigrate.source_reporting.registry import (
    SourceReportRegistrationError,
    SourceReportRegistry,
    source_reporters,
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
    normalize_web_report,
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
    "REPORT_SECTIONS",
    "normalize_web_report",
]
