"""FortiGate source-report adapter for the shared web host."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any

from fwmigrate.source_reporting import ExcelExportProfile, SourceReportMetrics

from .config import ExtractionConfig
from .derived import DerivedViews, build_derived_views
from .extraction.extractor import extract_fortigate_config
from .extraction.result import ExtractionResult
from .parser import parse_fortigate_config
from .validation.models import ValidationResult
from .validation.validator import validate_config


@dataclass(frozen=True, slots=True)
class FortiGateSourceResult:
    """Opaque FortiGate analysis result crossing the shared boundary."""

    extracted: ExtractionResult
    derived: DerivedViews
    validation: ValidationResult
    top_level_sections: int


class FortiGateSourceReporter:
    vendor_id = "fortigate"
    display_name = "Fortinet FortiGate"
    supported_extensions = (".conf", ".cfg", ".txt")

    def analyze_source(self, source: str, **options: Any) -> FortiGateSourceResult:
        extraction_config = options.get("config") or ExtractionConfig()
        metrics = options.get("metrics")
        if metrics is not None and not isinstance(metrics, SourceReportMetrics):
            raise TypeError("metrics must be SourceReportMetrics")
        started_total = perf_counter() if metrics is not None else None

        def timed(stage: str, operation):
            if metrics is None:
                return operation()
            started = perf_counter()
            try:
                return operation()
            finally:
                metrics.add(stage, (perf_counter() - started) * 1000)

        if metrics is not None:
            metrics.set_metadata("source_byte_count", len(source.encode("utf-8")))
            metrics.set_metadata("physical_line_count", source.count("\n") + (1 if source else 0))

        tree = timed("fortigate_parse", lambda: parse_fortigate_config(source))
        top_level_sections = len(tree.configs)
        if metrics is not None:
            metrics.set_metadata("top_level_section_count", top_level_sections)
        extracted = timed(
            "fortigate_extraction",
            lambda: extract_fortigate_config(tree, config=extraction_config, metrics=metrics),
        )
        derived = timed("fortigate_derived_views", lambda: build_derived_views(extracted.config))
        validation = timed(
            "fortigate_validation",
            lambda: validate_config(extracted.config, derived=derived),
        )
        if metrics is not None:
            metrics.set_metadata("validation_issue_count", len(validation.issues))
            metrics.total_duration_ms = (perf_counter() - started_total) * 1000
        return FortiGateSourceResult(
            extracted=extracted,
            derived=derived,
            validation=validation,
            top_level_sections=top_level_sections,
        )

    def build_preview(
        self,
        analysis: FortiGateSourceResult,
        **options: Any,
    ) -> dict[str, Any]:
        del options
        from .web_report import build_web_report

        return build_web_report(
            analysis.extracted.config,
            analysis.derived,
            analysis.validation,
            top_level_sections=analysis.top_level_sections,
        )

    def export_excel(
        self,
        analysis: FortiGateSourceResult,
        output: Any,
        profile: ExcelExportProfile | str = ExcelExportProfile.FULL,
        **options: Any,
    ) -> Any:
        from .export import export_excel

        return export_excel(
            extracted=analysis.extracted,
            derived=analysis.derived,
            validation=analysis.validation,
            output=output,
            profile=profile,
            source_name=options.get("source_name"),
        )


__all__ = ["FortiGateSourceReporter", "FortiGateSourceResult"]
