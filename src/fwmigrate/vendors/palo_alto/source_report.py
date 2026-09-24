"""PAN-OS vendor-native source reporting boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .native import build_derived_views, validate_panos_config
from .source_builder import build_panos_config
from .model.source import PANOSConfig
from .source_model import PANOSDerivedViews, PANOSValidationResult


@dataclass(frozen=True)
class PaloAltoSourceResult:
    config: PANOSConfig
    derived: PANOSDerivedViews
    validation: PANOSValidationResult


class PaloAltoSourceReporter:
    vendor_id = "palo_alto"
    display_name = "Palo Alto Networks (PAN-OS / Panorama)"
    supported_extensions = (".xml",)

    def analyze_source(self, source: str, **options: Any) -> PaloAltoSourceResult:
        config = build_panos_config(source)
        derived = build_derived_views(config)
        return PaloAltoSourceResult(
            config=config,
            derived=derived,
            validation=validate_panos_config(config, derived),
        )

    def build_preview(self, analysis: PaloAltoSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_panos_preview

        return build_panos_preview(analysis)

    def export_excel(self, analysis: PaloAltoSourceResult, output: Any, **options: Any) -> Any:
        from .export.excel import export_panos_excel

        export_panos_excel(analysis, output, source_name=options.get("source_name"))
        return output


__all__ = ["PaloAltoSourceReporter", "PaloAltoSourceResult"]
