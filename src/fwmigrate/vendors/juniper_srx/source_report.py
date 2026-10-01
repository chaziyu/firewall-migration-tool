"""Vendor-native Junos source reporting boundary."""

from __future__ import annotations

from typing import Any

from ...source_reporting.options import ExcelExportProfile

from .source_analysis import JuniperSourceResult, extract_juniper_source as _analyze_juniper_source
from .source_accounting import get_command_section_path


def extract_juniper_source(content: str, zone_mapping: dict[str, str] | None = None) -> JuniperSourceResult:
    return _analyze_juniper_source(content, zone_mapping)


class JuniperSRXSourceReporter:
    vendor_id = "juniper_srx"
    display_name = "Juniper SRX"
    supported_extensions = (".set", ".txt", ".conf")

    def analyze_source(self, source: str, **options: Any) -> JuniperSourceResult:
        return extract_juniper_source(source, zone_mapping=options.get("zone_mapping"))

    def build_preview(self, analysis: JuniperSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_juniper_preview
        return build_juniper_preview(analysis)

    def export_excel(self, analysis: JuniperSourceResult, output: Any, profile: ExcelExportProfile | str = ExcelExportProfile.FULL, **options: Any) -> Any:
        from .export.excel import export_juniper_excel
        return export_juniper_excel(
            analysis,
            output,
            profile=profile,
            collection_status=options.get("collection_status"),
            collection_parts=options.get("collection_parts"),
            collection_warnings=options.get("collection_warnings"),
        )


__all__ = ["JuniperSourceResult", "JuniperSRXSourceReporter", "extract_juniper_source"]
