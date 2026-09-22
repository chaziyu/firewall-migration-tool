"""PAN-OS source-model construction and read-only reporting views."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import Counter

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from .parser import load_pan_source
from .source_model import (
    PANOSConfig,
    PANOSDerivedViews,
    PANOSValidationIssue,
    PANOSValidationResult,
    PANScope,
    PANSourceRecord,
    pan_scope_identity,
)


def _scope_for(path: tuple[str, ...], element: ET.Element) -> PANScope | None:
    for index, part in enumerate(path):
        if part != "entry" or index == 0:
            continue
        parent = path[index - 1]
        if parent not in {"vsys", "device-group", "devices", "device", "shared"}:
            continue
        name = element.get("name") or parent
        return PANScope(kind=parent.rstrip("s"), name=name, vsys=name if parent == "vsys" else None)
    return None


def _record_value(element: ET.Element) -> dict[str, object]:
    values: dict[str, object] = {}
    for child in element:
        if len(child) == 0 and (child.text or "").strip():
            values[child.tag] = (child.text or "").strip()
        elif len(child):
            values[child.tag] = [item.get("name") or (item.text or "").strip() for item in child]
    return values


def build_panos_config(content: str) -> PANOSConfig:
    source = load_pan_source(content)
    scopes: list[PANScope] = []
    records: list[PANSourceRecord] = []
    order = 0

    def visit(element: ET.Element, path: tuple[str, ...]) -> None:
        nonlocal order
        current_path = path + (element.tag,)
        scope = _scope_for(current_path, element)
        if scope and pan_scope_identity(scope) not in {pan_scope_identity(item) for item in scopes}:
            scopes.append(scope)
        if element.tag == "entry":
            order += 1
            records.append(PANSourceRecord(
                kind=path[-1] if path else "entry",
                source_path="/".join(current_path),
                name=element.get("name"),
                scope=scope,
                values=sanitize_source_attributes(_record_value(element)),
                source_order=order,
                raw_xml=sanitize_raw_text(ET.tostring(element, encoding="unicode")),
            ))
        for child in element:
            visit(child, current_path)

    visit(source.root, ())
    return PANOSConfig(
        hostname=source.hostname,
        source_version=source.source_version,
        scopes=scopes,
        records=records,
    )


def build_derived_views(config: PANOSConfig) -> PANOSDerivedViews:
    counts = dict(Counter(record.kind for record in config.records))
    return PANOSDerivedViews(
        counts=counts,
        scope_identities=tuple(pan_scope_identity(scope) for scope in config.scopes),
    )


def validate_panos_config(config: PANOSConfig, derived: PANOSDerivedViews) -> PANOSValidationResult:
    issues: list[PANOSValidationIssue] = []
    if not config.records:
        issues.append(PANOSValidationIssue("warning", "source", "PAN-OS XML contains no entry records."))
    if not config.scopes:
        issues.append(PANOSValidationIssue("warning", "scope", "PAN-OS XML contains no explicit device, VSYS, or device-group scope."))
    return PANOSValidationResult(tuple(issues))


__all__ = ["build_panos_config", "build_derived_views", "validate_panos_config"]
