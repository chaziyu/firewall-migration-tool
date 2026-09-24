"""FortiGate source-report adapter for the shared web host."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import ExtractionConfig
from .derived import DerivedViews, build_derived_views
from .extraction.extractor import extract_fortigate_config
from .extraction.result import ExtractionResult
from .nodes import FortiGateConfigTree
from .parser import parse_fortigate_config
from .validation.models import ValidationResult
from .validation.validator import validate_config


@dataclass(frozen=True, slots=True)
class FortiGateSourceResult:
    """Opaque FortiGate analysis result crossing the shared boundary."""

    tree: FortiGateConfigTree
    extracted: ExtractionResult
    derived: DerivedViews
    validation: ValidationResult


class FortiGateSourceReporter:
    vendor_id = "fortigate"
    display_name = "Fortinet FortiGate"
    supported_extensions = (".conf", ".cfg", ".txt")

    def analyze_source(self, source: str, **options: Any) -> FortiGateSourceResult:
        extraction_config = options.get("config") or ExtractionConfig()
        tree = parse_fortigate_config(source)
        extracted = extract_fortigate_config(tree, config=extraction_config)
        derived = build_derived_views(extracted.config)
        validation = validate_config(extracted.config, derived=derived)
        return FortiGateSourceResult(tree, extracted, derived, validation)

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
            top_level_sections=len(analysis.tree.configs),
        )

    def export_excel(
        self,
        analysis: FortiGateSourceResult,
        output: Any,
        **options: Any,
    ) -> Any:
        from .export import export_excel

        return export_excel(
            extracted=analysis.extracted,
            derived=analysis.derived,
            validation=analysis.validation,
            output=output,
            source_name=options.get("source_name"),
        )


__all__ = ["FortiGateSourceReporter", "FortiGateSourceResult"]
