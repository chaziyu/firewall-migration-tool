"""PAN-OS source loading, inventory capture, and typed extraction orchestration."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes, sanitize_source_value

from .extraction.extractor import extract_typed, registered_typed_collections, registered_typed_domains
from .model import PANOSConfig
from .schema_registry import match_path_spec
from .source_context import walk_pan_source
from .source_model import PANExtractionIssue, PANSourceRecord, PANScope, pan_scope_identity
from .xml_loader import load_pan_source


def _record_value(element: ET.Element) -> dict[str, object]:
    values: dict[str, object] = {}
    for child in element:
        if child.tag == "member":
            values.setdefault("member", []).append((child.text or "").strip())
            continue
        if len(child) == 0 and (child.text or "").strip():
            values[child.tag] = (child.text or "").strip()
        elif len(child):
            values[child.tag] = [sanitize_source_value(item.tag, item.get("name") or (item.text or "").strip()) for item in child]
    return values


def _inventory_record(element: ET.Element, path: tuple[str, ...], context, source_order: int) -> PANSourceRecord:
    return PANSourceRecord(kind=path[-2] if len(path) > 1 else "entry", source_path="/".join(path), name=element.get("name"), scope=context.scope, rulebase_position=context.rulebase_position, values=sanitize_source_attributes(_record_value(element)), source_order=source_order, raw_xml=sanitize_raw_text(ET.tostring(element, encoding="unicode")))


def _inventory_unsupported_branch(element: ET.Element, path: tuple[str, ...], context, source_order: int) -> PANSourceRecord:
    return PANSourceRecord(kind=element.tag, source_path="/".join(path), name=element.get("name"), scope=context.scope,
        rulebase_position=context.rulebase_position, values=sanitize_source_attributes(_record_value(element)),
        source_order=source_order, raw_xml=sanitize_raw_text(ET.tostring(element, encoding="unicode")))


def build_panos_config(content: str) -> PANOSConfig:
    source = load_pan_source(content)
    scopes: list[PANScope] = []
    records: list[PANSourceRecord] = []
    unknown_paths: list[str] = []
    extraction_issues: list[PANExtractionIssue] = []
    typed: dict[str, list[object]] = {collection: [] for collection in registered_typed_collections()}
    preserved_branches: list[str] = []
    typed_domains = registered_typed_domains()
    for element, path, context in walk_pan_source(source.root):
        if context.scope and pan_scope_identity(context.scope) not in {pan_scope_identity(item) for item in scopes}:
            scopes.append(context.scope)
        spec = match_path_spec(path)
        path_string = "/".join(path)
        if any(path_string.startswith(branch + "/") for branch in preserved_branches):
            continue
        has_record = element.tag == "entry" or (spec is not None and spec.name in typed_domains)
        if has_record:
            record_builder = _inventory_record if element.tag == "entry" else _inventory_unsupported_branch
            records.append(record_builder(element, path, context, len(records) + 1))
            source_order = len(records)
        elif spec is None:
            # Keep maximal unsupported branches that are outside an inventoried
            # entry. Their descendants cannot contain separate entry records, so
            # one source-only record preserves their path and sanitized evidence.
            excluded_roots = {"config", "devices", "device", "shared", "vsys"}
            has_entry_ancestor = "entry" in path[:-1]
            has_entry_descendant = any(child.tag == "entry" for child in element.iter() if child is not element)
            if path[-1] not in excluded_roots and not has_entry_ancestor and not has_entry_descendant:
                records.append(_inventory_unsupported_branch(element, path, context, len(records) + 1))
                preserved_branches.append(path_string)
            continue
        else:
            source_order = len(records) + 1
        try:
            result = extract_typed(element, path, context, source_order)
        except Exception as error:
            # Inventory is source evidence; a typed-model defect must not make
            # the source disappear or prevent the remaining tree from loading.
            unknown_paths.append("/".join(path))
            extraction_issues.append(PANExtractionIssue(
                source_path="/".join(path), source_name=element.get("name"), source_order=source_order,
                scope=context.scope, domain=spec.name if spec else None,
                exception_type=type(error).__name__, message=sanitize_raw_text(str(error))[:500],
            ))
            if has_record:
                records[-1].unsupported = True
            continue
        if result is not None:
            collection, model = result
            typed[collection].append(model)
    return PANOSConfig(hostname=source.hostname, source_version=source.source_version, scopes=scopes, **typed, source_inventory=records, unknown_paths=unknown_paths, extraction_issues=extraction_issues)
