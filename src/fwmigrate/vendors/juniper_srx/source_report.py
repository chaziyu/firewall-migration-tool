"""Vendor-native Junos source extraction and reporting boundary."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from fwmigrate.extraction.models import (
    ExtractionStatus, SourceCommand, SourceInventoryItem, SourceSectionResult, UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_raw_text

from .derived import JuniperDerivedViews, build_juniper_derived_views
from .parser import JuniperSRXParser
from .tokenizer import JunosCommand, JunosOperation
from .validation import JuniperReviewItem, JuniperValidationResult, build_review_items, validate_juniper_config


def get_command_section_path(command: JunosCommand) -> str:
    """Return the native Junos hierarchy section for one source command."""
    if len(command.tokens) < 2:
        return "root"
    tokens = command.tokens[1:]
    first = tokens[0].lower()
    if first in {"logical-systems", "tenants"} and len(tokens) > 2:
        nested = JunosCommand(
            operation=command.operation,
            tokens=[command.tokens[0], *tokens[2:]],
            raw_sanitized=command.raw_sanitized,
            line_number=command.line_number,
        )
        return f"{first} {tokens[1]} {get_command_section_path(nested)}"
    if first == "security":
        return f"security {tokens[1].lower()}" if len(tokens) > 1 else "security"
    if first == "routing-options":
        return f"routing-options {tokens[1].lower()}" if len(tokens) > 1 else first
    if first == "routing-instances":
        return f"routing-instances {tokens[1]}" if len(tokens) > 2 else first
    return first


def _context_label(command: JunosCommand) -> str | None:
    if not command.context_type or command.context_type == "root":
        return None
    return f"{command.context_type} {command.context_name}"


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_raw_text(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    fields = getattr(type(value), "model_fields", None)
    if fields is not None:
        for name in fields:
            setattr(value, name, _sanitize(getattr(value, name)))
    return value


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


def _account(commands: list[JunosCommand]) -> tuple[list[SourceSectionResult], list[SourceInventoryItem], list[UnsupportedItem]]:
    grouped: dict[str, list[JunosCommand]] = {}
    for command in commands:
        grouped.setdefault(get_command_section_path(command), []).append(command)
    sections, inventory, unsupported = [], [], []
    for path, items in grouped.items():
        statuses = [item.extraction_status or (ExtractionStatus.EXTRACTED if item.consumed else ExtractionStatus.UNSUPPORTED)
                    for item in items]
        distinct = set(statuses)
        status = next((candidate for candidate in (ExtractionStatus.PARSE_ERROR, ExtractionStatus.UNSUPPORTED,
                                                     ExtractionStatus.PARTIAL, ExtractionStatus.SOURCE_ONLY,
                                                     ExtractionStatus.UNKNOWN, ExtractionStatus.IGNORED)
                       if candidate in distinct), ExtractionStatus.EXTRACTED)
        commands_out = []
        for item in items:
            safe = item.to_sanitized_copy()
            command_status = item.extraction_status or (ExtractionStatus.EXTRACTED if item.consumed else ExtractionStatus.UNSUPPORTED)
            commands_out.append(SourceCommand(operation=item.operation.value if isinstance(item.operation, JunosOperation) else str(item.operation),
                                              key=" ".join(safe.tokens[1:3]), values=safe.tokens[3:], line_number=item.line_number,
                                              status=command_status, parser_handler=item.handler,
                                              requires_manual_review=item.requires_manual_review or command_status != ExtractionStatus.EXTRACTED,
                                              source_context=_context_label(item)))
            if command_status in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR):
                unsupported.append(UnsupportedItem(source_path=path, source_name=" ".join(safe.tokens),
                                                   reason=sanitize_raw_text(item.parse_error or f"Unsupported Junos command in {path}"),
                                                   raw_capture=safe.raw_sanitized, source_context=_context_label(item)))
        sections.append(SourceSectionResult(
            path=path, source_context=next((_context_label(i) for i in items if _context_label(i)), None),
            line_start=min(i.line_number for i in items), line_end=max(i.line_number for i in items),
            status=status, parser_handler=items[0].handler,
            source_commands=[item.to_sanitized_copy().raw_sanitized for item in items],
            review_reasons=sorted({item.extraction_status.value for item in items
                                   if item.extraction_status in (ExtractionStatus.SOURCE_ONLY, ExtractionStatus.PARTIAL,
                                                                 ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR,
                                                                 ExtractionStatus.UNKNOWN, ExtractionStatus.IGNORED)}),
        ))
        inventory.append(SourceInventoryItem(domain="juniper_srx", source_path=path, name=path,
                                             source_type="junos-hierarchy",
                                             source_context=next((_context_label(i) for i in items if _context_label(i)), None),
                                             commands=commands_out, status=status,
                                             requires_manual_review=any(c.requires_manual_review for c in commands_out),
                                             notes=sorted({s.value for s in statuses if s != ExtractionStatus.EXTRACTED})))
    return sections, inventory, unsupported


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


class JuniperSRXSourceReporter:
    vendor_id = "juniper_srx"
    display_name = "Juniper SRX"
    supported_extensions = (".set", ".txt", ".conf")

    def analyze_source(self, source: str, **options: Any) -> JuniperSourceResult:
        return extract_juniper_source(source, zone_mapping=options.get("zone_mapping"))

    def build_preview(self, analysis: JuniperSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_juniper_preview
        return build_juniper_preview(analysis)

    def export_excel(self, analysis: JuniperSourceResult, output: Any, **options: Any) -> Any:
        from .export.excel import export_juniper_excel
        return export_juniper_excel(analysis, output)


__all__ = ["JuniperSourceResult", "JuniperSRXSourceReporter", "extract_juniper_source"]
