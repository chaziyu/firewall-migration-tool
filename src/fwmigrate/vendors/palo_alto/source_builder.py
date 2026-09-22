"""PAN-OS source-record construction from loaded XML."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from .source_context import walk_pan_source
from .source_model import PANOSConfig, PANScope, PANSourceRecord, pan_scope_identity
from .xml_loader import load_pan_source


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

    for element, path, context in walk_pan_source(source.root):
        if context.scope and pan_scope_identity(context.scope) not in {
            pan_scope_identity(item) for item in scopes
        }:
            scopes.append(context.scope)
        if element.tag != "entry":
            continue
        records.append(
            PANSourceRecord(
                kind=path[-2] if len(path) > 1 else "entry",
                source_path="/".join(path),
                name=element.get("name"),
                scope=context.scope,
                rulebase_position=context.rulebase_position,
                values=sanitize_source_attributes(_record_value(element)),
                source_order=len(records) + 1,
                raw_xml=sanitize_raw_text(ET.tostring(element, encoding="unicode")),
            )
        )

    return PANOSConfig(
        hostname=source.hostname,
        source_version=source.source_version,
        scopes=scopes,
        records=records,
    )
