"""Check Point vendor-native source reporting boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .derived import CheckPointDerivedViews, build_checkpoint_derived_views
from .loader import load_checkpoint_input
from .model.source import CheckPointConfig
from .extraction import extract_checkpoint_config
from .extraction.source_metadata import CheckPointSourceMetadata
from .validation import CheckPointValidationResult, validate_checkpoint_config
from .models import ScopeSelectionResult


@dataclass(frozen=True)
class CheckPointSourceResult:
    config: CheckPointConfig
    derived: CheckPointDerivedViews
    validation: CheckPointValidationResult
    collection: tuple[Any, ...] = ()
    source_objects: tuple[Any, ...] = ()
    source_metadata: CheckPointSourceMetadata = field(default_factory=CheckPointSourceMetadata)
    scope: ScopeSelectionResult = field(default_factory=ScopeSelectionResult)

    @property
    def source_inventory(self) -> tuple[Any, ...]:
        return self.source_objects


class CheckPointSourceReporter:
    vendor_id = "checkpoint"
    display_name = "Check Point R80/R81"
    supported_extensions = (".json", ".txt", ".cfg")

    def analyze_source(self, source: str, **options: Any) -> CheckPointSourceResult:
        bundle, scope = load_checkpoint_input(source)
        extracted = extract_checkpoint_config(bundle, scope)
        derived = build_checkpoint_derived_views(extracted.config, extracted.collection)
        return CheckPointSourceResult(
            extracted.config, derived,
            validate_checkpoint_config(
                extracted.config, derived, collection=extracted.collection,
                scope=extracted.scope, source_inventory=extracted.source_inventory,
            ),
            extracted.collection, extracted.source_objects, extracted.source_metadata, extracted.scope,
        )

    def build_preview(self, analysis: CheckPointSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_checkpoint_preview

        return build_checkpoint_preview(analysis)

    def export_excel(self, analysis: CheckPointSourceResult, output: Any, **options: Any) -> Any:
        from .export.excel import export_checkpoint_excel

        return export_checkpoint_excel(analysis, output)


def extract_checkpoint_source(source: str) -> CheckPointSourceResult:
    return CheckPointSourceReporter().analyze_source(source)


__all__ = ["CheckPointSourceReporter", "CheckPointSourceResult", "extract_checkpoint_source"]
