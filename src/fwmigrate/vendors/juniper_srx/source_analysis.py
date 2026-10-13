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


def _section_leaf_path(path: str) -> str:
    """Normalize an accounted section path to its context-local Junos hierarchy."""
    parts = path.split()
    if len(parts) >= 3 and parts[0] in {"logical-systems", "tenants"}:
        return " ".join(parts[2:])
    return path


def _dependency_belongs_to_section(dependency: Any, section: SourceSectionResult) -> bool:
    if dependency.result != "UNRESOLVED":
        return False
    if (dependency.source_context or None) != (section.source_context or None):
        return False
    section_path = _section_leaf_path(section.path)
    dependency_path = dependency.source_path or ""
    return dependency_path == section_path or dependency_path.startswith(section_path + " ")


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


def extract_juniper_source(content: str) -> JuniperSourceResult:
    parser = JuniperSRXParser(content)
    config = _sanitize(deepcopy(parser.extract_source()))
    sections, inventory, unsupported = _account(parser.commands)
    derived = build_juniper_derived_views(config, source_commands=parser.commands)
    for section in sections:
        section.unresolved_dependencies = sum(
            _dependency_belongs_to_section(dependency, section)
            for dependency in derived.dependencies
        )
    validation = validate_juniper_config(config, derived)
    review = build_review_items(validation, sections, unsupported)
    return JuniperSourceResult(config, parser.source_format, tuple(sections), tuple(inventory), tuple(unsupported),
                               derived, validation, review)


