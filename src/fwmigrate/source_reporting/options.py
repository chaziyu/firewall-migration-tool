"""Shared presentation options for vendor-native Excel reports."""

from __future__ import annotations

from enum import Enum


class ExcelExportProfile(str, Enum):
    FULL = "full"
    FAST = "fast"
    DATA_ONLY = "data_only"


class ExcelExportUnavailableError(RuntimeError):
    """Raised when a vendor cannot produce an Excel report."""


XLSX_MIMETYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


__all__ = ["ExcelExportProfile", "ExcelExportUnavailableError", "XLSX_MIMETYPE"]
