"""PAN-OS source-model construction and read-only reporting views."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import Counter

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from .source_model import (
    PANSourceDocument,
    PANOSConfig,
    PANOSDerivedViews,
    PANOSValidationIssue,
    PANOSValidationResult,
    PANScope,
    PANSourceRecord,
    pan_scope_identity,
)


def load_pan_source(content: str) -> PANSourceDocument:
    """Load a PAN-OS XML export without entering a conversion pipeline."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        cleaned = content.strip()
        if not cleaned:
            raise ValueError("Empty configuration input.") from error
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            if cleaned.startswith("set "):
                raise ValueError(
                    "PAN-OS CLI 'set' format is not supported. Please provide XML configuration."
                ) from error
            raise ValueError(f"Malformed XML input: {error}") from error

    if root.tag == "response":
        wrapped = root.find("./result/config")
        if wrapped is None:
            raise ValueError(
                "Unsupported PAN-OS XML response: missing response/result/config."
            )
        root = wrapped
    if root.tag != "config":
        raise ValueError(
            f"Unsupported XML format: expected root element '<config>', found '<{root.tag}>'."
        )

    host_elem = root.find(".//system/hostname")
    if host_elem is None:
        host_elem = root.find(".//deviceconfig/system/hostname")
    hostname = host_elem.text.strip() if host_elem is not None and host_elem.text else None
    return PANSourceDocument(
        root=root,
        raw_content=content,
        hostname=hostname,
        source_version=root.get("version"),
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


__all__ = ["build_panos_config", "build_derived_views", "load_pan_source", "validate_panos_config"]
