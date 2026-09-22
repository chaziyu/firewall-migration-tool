"""Check Point vendor-native source reporting boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .derived import CheckPointDerivedViews, build_checkpoint_derived_views
from .loader import load_checkpoint_input
from .source_model import CheckPointConfig, build_checkpoint_config
from .validation import CheckPointValidationResult, validate_checkpoint_config


@dataclass(frozen=True)
class CheckPointSourceResult:
    config: CheckPointConfig
    derived: CheckPointDerivedViews
    validation: CheckPointValidationResult


class CheckPointSourceReporter:
    vendor_id = "checkpoint"
    display_name = "Check Point R80/R81"
    supported_extensions = (".json", ".txt", ".cfg")

    def analyze_source(self, source: str, **options: Any) -> CheckPointSourceResult:
        bundle, _scope = load_checkpoint_input(source)
        config = build_checkpoint_config(bundle)
        derived = build_checkpoint_derived_views(config)
        return CheckPointSourceResult(config, derived, validate_checkpoint_config(config, derived))

    def build_preview(self, analysis: CheckPointSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_checkpoint_preview

        return build_checkpoint_preview(analysis)

    def export_excel(self, analysis: CheckPointSourceResult, output: Any, **options: Any) -> Any:
        from .export.excel import export_checkpoint_excel

        return export_checkpoint_excel(analysis, output)


def extract_checkpoint_source(source: str) -> CheckPointSourceResult:
    return CheckPointSourceReporter().analyze_source(source)


__all__ = ["CheckPointSourceReporter", "CheckPointSourceResult", "extract_checkpoint_source"]
