"""Cisco ASA vendor-native source extraction."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .model.source import CiscoASAConfig

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from .accounting import build_asa_source_accounting
from .coverage import classify_cisco_asa_coverage
from .derived import ASADerivedViews, build_asa_derived_views
from .validation import ASAValidationResult, validate_asa_config
from .section_scanner import scan_cisco_asa_sections


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_raw_text(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in sanitize_source_attributes(value).items()}
    fields = getattr(type(value), "model_fields", None)
    if fields is not None:
        for name in fields:
            setattr(value, name, _sanitize(getattr(value, name)))
    return value


@dataclass(frozen=True)
class ASASourceResult:
    config: CiscoASAConfig
    source_sections: list[Any]
    inventory_items: list[Any]
    unsupported_items: list[Any]
    derived: ASADerivedViews
    validation: ASAValidationResult


class CiscoASASourceReporter:
    vendor_id = "cisco_asa"
    display_name = "Cisco ASA"
    supported_extensions = (".cfg", ".txt", ".conf")

    def analyze_source(self, source: str, **options: Any) -> ASASourceResult:
        return extract_cisco_asa_source(source, zone_mapping=options.get("zone_mapping"))

    def build_preview(self, analysis: ASASourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_asa_preview

        return build_asa_preview(analysis)

    def export_excel(self, analysis: ASASourceResult, output: Any, **options: Any) -> Any:
        from .export.excel import export_asa_excel

        return export_asa_excel(analysis, output)


def extract_cisco_asa_source(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ASASourceResult:
    sections = scan_cisco_asa_sections(text)
    classify_cisco_asa_coverage(sections)
    from .parser import CiscoASAParser

    parser = CiscoASAParser(text, zone_mapping=zone_mapping)
    config = parser.parse_raw()
    inventory, unsupported = build_asa_source_accounting(text, sections, config)
    config = _sanitize(deepcopy(config))
    derived = build_asa_derived_views(config)
    return ASASourceResult(
        config=config,
        source_sections=sections,
        inventory_items=inventory,
        unsupported_items=unsupported,
        derived=derived,
        validation=validate_asa_config(config, derived),
    )


__all__ = ["ASASourceResult", "CiscoASASourceReporter", "extract_cisco_asa_source"]

