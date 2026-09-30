"""Juniper source report analysis."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from fwmigrate.extraction.models import SourceInventoryItem, SourceSectionResult, UnsupportedItem
from .derived import JuniperDerivedViews, build_juniper_derived_views
from .parser import JuniperSRXParser
from .source_accounting import _account
from .source_sanitization import _sanitize
from .validation import JuniperReviewItem, JuniperValidationResult, build_review_items, validate_juniper_config


@dataclass(frozen=True)
class JuniperSourceResult:
    config: Any
    source_format: str
    source_sections: tuple[SourceSectionResult, ...]
    inventory_items: tuple[SourceInventoryItem, ...]
    unsupported_items: tuple[UnsupportedItem, ...]
    derived: JuniperDerivedViews
    validation: JuniperValidationResult
    review_required: tuple[JuniperReviewItem, ...] = ()


def extract_juniper_source(content: str, zone_mapping: dict[str, str] | None = None) -> JuniperSourceResult:
    parser = JuniperSRXParser(content, zone_mapping=zone_mapping)
    config = _sanitize(deepcopy(parser.extract_source()))
    sections, inventory, unsupported = _account(parser.commands)
    derived = build_juniper_derived_views(config, source_commands=parser.commands)
    for section in sections:
        section.unresolved_dependencies = sum(
            dependency.result == "UNRESOLVED" and dependency.source_path == section.path
            for dependency in derived.dependencies
        )
    validation = validate_juniper_config(config, derived)
    review = build_review_items(validation, sections, unsupported)
    return JuniperSourceResult(config, parser.source_format, tuple(sections), tuple(inventory), tuple(unsupported),
                               derived, validation, review)


