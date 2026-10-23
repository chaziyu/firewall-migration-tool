"""Shared presentation options for vendor-native Excel reports."""

from __future__ import annotations

from enum import Enum


class ExcelExportProfile(str, Enum):
    FULL = "full"
    FAST = "fast"


class ExcelExportUnavailableError(RuntimeError):
    """Raised when a vendor cannot produce an Excel report."""


class ExcelReportLimitError(ValueError):
    """A report cannot fit in a valid Excel worksheet."""


XLSX_MIMETYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


__all__ = ["ExcelExportProfile", "ExcelExportUnavailableError", "XLSX_MIMETYPE"]
