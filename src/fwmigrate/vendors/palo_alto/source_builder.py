"""PAN-OS source loading, inventory capture, and typed extraction orchestration."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes, sanitize_source_value

from .extraction.extractor import extract_typed
from .model import PANOSConfig
from .schema_registry import match_path_spec
from .source_context import walk_pan_source
from .source_model import PANSourceRecord, PANScope, pan_scope_identity
from .xml_loader import load_pan_source


def _record_value(element: ET.Element) -> dict[str, object]:
    values: dict[str, object] = {}
    for child in element:
        if len(child) == 0 and (child.text or "").strip():
            values[child.tag] = (child.text or "").strip()
        elif len(child):
            values[child.tag] = [sanitize_source_value(item.tag, item.get("name") or (item.text or "").strip()) for item in child]
    return values


def _inventory_record(element: ET.Element, path: tuple[str, ...], context, source_order: int) -> PANSourceRecord:
    return PANSourceRecord(kind=path[-2] if len(path) > 1 else "entry", source_path="/".join(path), name=element.get("name"), scope=context.scope, rulebase_position=context.rulebase_position, values=sanitize_source_attributes(_record_value(element)), source_order=source_order, raw_xml=sanitize_raw_text(ET.tostring(element, encoding="unicode")))


def build_panos_config(content: str) -> PANOSConfig:
    source = load_pan_source(content)
    scopes: list[PANScope] = []
    records: list[PANSourceRecord] = []
    unknown_paths: list[str] = []
    typed: dict[str, list[object]] = {"addresses": [], "address_groups": [], "services": [], "service_groups": [], "schedules": [], "security_rules": [], "default_security_rules": [], "interfaces": [], "interface_imports": [], "interface_units": [], "nat_rules": [], "static_routes": [], "virtual_routers": [], "logical_routers": []}
    for element, path, context in walk_pan_source(source.root):
        if context.scope and pan_scope_identity(context.scope) not in {pan_scope_identity(item) for item in scopes}:
            scopes.append(context.scope)
        spec = match_path_spec(path)
        if element.tag == "entry":
            records.append(_inventory_record(element, path, context, len(records) + 1))
            source_order = len(records)
        elif spec is None:
            continue
        else:
            source_order = len(records) + 1
        try:
            result = extract_typed(element, path, context, source_order)
        except Exception:
            # Inventory is source evidence; a typed-model defect must not make
            # the source disappear or prevent the remaining tree from loading.
            unknown_paths.append("/".join(path))
            continue
        if result is not None:
            collection, model = result
            typed[collection].append(model)
    return PANOSConfig(hostname=source.hostname, source_version=source.source_version, scopes=scopes, **typed, source_inventory=records, unknown_paths=unknown_paths)
