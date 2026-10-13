"""Cisco FTD vendor-native source reporting boundary."""

from __future__ import annotations

from typing import Any

from ...source_reporting.options import ExcelExportProfile

from .source_analysis import FTDSourceResult, extract_cisco_ftd_source as _analyze_ftd_source


def extract_cisco_ftd_source(text: str) -> FTDSourceResult:
    return _analyze_ftd_source(text)


class CiscoFTDSourceReporter:
    vendor_id = "cisco_ftd"
    display_name = "Cisco Firepower Threat Defense"
    supported_extensions = (".cfg", ".txt", ".conf", ".json")

    def analyze_source(self, source: str, **options: Any) -> FTDSourceResult:
        return extract_cisco_ftd_source(source)

    def build_preview(self, analysis: FTDSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_ftd_preview
        return build_ftd_preview(analysis)

    def export_excel(self, analysis: FTDSourceResult, output: Any, profile: ExcelExportProfile | str = ExcelExportProfile.FULL, **options: Any) -> Any:
        from .export.excel import export_ftd_excel
        return export_ftd_excel(analysis, output, profile=profile)


__all__ = ["CiscoFTDSourceReporter", "FTDSourceResult", "extract_cisco_ftd_source"]
