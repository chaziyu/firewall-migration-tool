from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
import json
from pathlib import Path
from typing import Any, get_args

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from ..validation.index import CheckPointValidationIndex
from .excel_schema import DERIVED_SHEETS, SHEET_HEADERS, SHEET_ORDER, SOURCE_SHEETS


def _excel_safe(value: Any) -> Any:
    value = _plain_value(value)
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _plain_value(value: Any) -> Any:
    if isinstance(value, Enum): return value.value
    if hasattr(value, "model_dump"): value = value.model_dump(mode="python", by_alias=False)
    elif is_dataclass(value): value = asdict(value)
    if isinstance(value, dict): return sanitize_source_attributes({str(k): _plain_value(v) for k, v in value.items()})
    if isinstance(value, (tuple, list, set)): return ", ".join(str(_plain_value(v)) for v in value)
    return value


def _additional_settings(item: Any) -> str:
    known = set(type(item).model_fields)
    values = sanitize_source_attributes(getattr(item, "raw_extra", {}) or {})
    return "; ".join(f"{key} = {json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else value}"
                      for key, value in sorted(values.items())
                      if key not in known and value not in (None, "", [], {}))


def _source_headers(result: Any, field: str) -> tuple[str, ...]:
    from ..model.source import CheckPointConfig
    annotation = CheckPointConfig.model_fields[field].annotation
    item_type = next((arg for nested in get_args(annotation) for arg in get_args(nested)
                      if isinstance(arg, type) and hasattr(arg, "model_fields")), None)
    item_type = item_type or next((arg for arg in get_args(annotation)
                                   if isinstance(arg, type) and hasattr(arg, "model_fields")), None)
    fields = tuple(item_type.model_fields) if item_type else ()
    return tuple(dict.fromkeys(("Domain", "UID", "Object Type", "Source Plane", "Source Command", "Package", "Layer", "Analysis Status", "Review Reasons", "Source Explicit Fields", "Additional Settings", *fields)))


def _source_rows(items: Any, headers: tuple[str, ...], validation: CheckPointValidationIndex, sheet_name: str):
    result = []
    for item in items:
        issues = (*validation.issues_for_uid(item.uid or ""), *validation.issues_for_object(type(item).__name__, item.name or ""))
        values = item.model_dump(mode="python", by_alias=False)
        row = {"Domain": item.domain or item.domain_uid, "UID": item.uid, "Object Type": item.object_type or type(item).__name__,
               "Source Plane": item.source_plane, "Source Command": item.command, "Package": item.package, "Layer": item.layer,
               "Source Explicit Fields": item.explicit_fields, "Additional Settings": _additional_settings(item)}
        row.update(values)
        row["Analysis Status"] = "Review Required" if issues else "EXTRACTED"
        row["Review Reasons"] = "; ".join(issue.message for issue in issues)
        result.append(tuple(_excel_safe(row.get(header)) for header in headers))
    return result


def _issue_rows(result: Any):
    names = {type(item).__name__: sheet for sheet, field in SOURCE_SHEETS.items()
             for item in getattr(result.config, field)}
    return [tuple(_excel_safe(value) for value in (
        i.severity, i.category, i.code, i.domain, i.object_type, i.object_name, i.object_uid,
        i.field, i.message, i.reference, names.get(i.object_type or "", ""))) for i in result.validation.issues]


def _derived_rows(result: Any, sheet: str):
    if sheet == "NAT Migration Views":
        return [(v.source_kind, v.owner_name or v.source_name, v.translation_method,
                 _plain_value(v.original_source), _plain_value(v.original_destination), _plain_value(v.translated_source),
                 "; ".join(i.message for i in v.issues)) for v in result.derived.nat.views]
    if sheet == "Policy Traversal":
        return [(e.package_name, e.layer_name, e.section_name, e.rule_name, e.rule_order, e.traversal_position,
                 e.parent_rule_uid, e.inline_depth, "; ".join(i.message for i in e.issues)) for e in result.derived.policy_traversal.entries]
    if sheet == "Interface Views":
        return [(v.device_name, v.device_kind, v.interface_name, v.resolved_zone_name, v.zone_assignment_source,
                 v.management_source_present, v.gaia_source_present, "; ".join(i.message for i in v.issues)) for v in result.derived.interface_views.views]
    if sheet == "VPN Views":
        return [(v.community_name, v.community_type, _plain_value(v.member_gateways), _plain_value(v.member_clusters),
                 _plain_value(v.member_interoperable_devices), _plain_value(v.center_members), _plain_value(v.satellite_members),
                 _plain_value(v.vpn_domains), _plain_value(v.vtis), v.route_based, "; ".join(i.message for i in v.issues)) for v in result.derived.vpn_views.views]
    return [(getattr(i.source, "name", None) or getattr(i.source, "uid", None), i.source_field, i.reference, i.status, i.message)
            for i in result.derived.broken_references]


def export_checkpoint_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook(); workbook.remove(workbook.active)
    validation = CheckPointValidationIndex(result.validation.issues)
    for name in SHEET_ORDER:
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            sheet.append(("Metric", "Count / Value"))
            sheet.append(("Source Objects", sum(len(getattr(result.config, f)) for f in SOURCE_SHEETS.values())))
            sheet.append(("Derived Views", sum(len(_derived_rows(result, s)) for s in DERIVED_SHEETS)))
            sheet.append(("Validation Findings", len(result.validation.issues)))
            sheet.append(("Incomplete Collections", len(result.derived.collection_incomplete)))
            sheet.append(("Unsupported Source Inventory", len(result.source_inventory)))
            sheet.append(("Scope Ambiguous", "Yes" if getattr(result.scope, "ambiguous", False) else "No"))
            sheet.append(("SD-WAN", "No direct R81.00 equivalent"))
            sheet.append(("API Version", result.source_metadata.api_version))
            sheet.append(("Management Server", result.source_metadata.management_server))
        elif name in SOURCE_SHEETS:
            field = SOURCE_SHEETS[name]; headers = _source_headers(result, field); sheet.append(headers)
            for row in _source_rows(getattr(result.config, field), headers, validation, name): sheet.append(row)
        elif name in DERIVED_SHEETS:
            sheet.append(SHEET_HEADERS[name])
            for row in _derived_rows(result, name): sheet.append(tuple(_excel_safe(v) for v in row))
        elif name == "Collection":
            sheet.append(SHEET_HEADERS[name])
            for i in result.collection: sheet.append(tuple(_excel_safe(v) for v in (i.command, i.source_plane, i.status, i.complete, i.error)))
        elif name == "Scope":
            sheet.append(SHEET_HEADERS[name])
            scope = getattr(result.scope, "model_dump", lambda: vars(result.scope))()
            for key, value in scope.items(): sheet.append((_excel_safe(key), _excel_safe(value)))
        elif name == "Review Required":
            sheet.append(SHEET_HEADERS[name])
            for row in _issue_rows(result): sheet.append(row)
        elif name == "Check Point Source Inventory":
            sheet.append(SHEET_HEADERS[name])
            for item in result.source_inventory:
                d = item.model_dump(mode="python", by_alias=False)
                sheet.append(tuple(_excel_safe(v) for v in (d.get("source_plane"), d.get("domain"), d.get("domain_uid"), d.get("command"), d.get("object_type"), d.get("uid"), d.get("name"), d.get("package"), d.get("layer"), d.get("gateway"), d.get("order"), d.get("explicit_fields"), d.get("values"), _additional_settings(item))))
        elif name == "Unsupported":
            sheet.append(SHEET_HEADERS[name])
            groups = {}
            for item in result.source_inventory:
                key = (item.command, item.domain, "UNSUPPORTED_SOURCE", item.object_type or "Unmodeled source object")
                groups[key] = groups.get(key, 0) + 1
            for item in result.collection:
                if not item.complete or str(item.status).lower().endswith("unsupported"):
                    key = (item.command, item.source_plane, str(item.status), item.error)
                    groups[key] = groups.get(key, 0) + 1
            for (command, scope, status, reason), count in groups.items(): sheet.append(tuple(_excel_safe(v) for v in (command, scope, count, reason or status, command)))
        else: sheet.append(SHEET_HEADERS[name])
        sheet.freeze_panes = "A2"
        if name in SOURCE_SHEETS:
            headers = _source_headers(result, SOURCE_SHEETS[name])
            for col, header in enumerate(headers, 1):
                if header in {"raw_extra", "explicit_fields", "Source Explicit Fields", "Additional Settings"}: sheet.column_dimensions[sheet.cell(1, col).column_letter].hidden = True
    if hasattr(output, "write"):
        workbook.save(output); return output
    path = Path(output); workbook.save(path); return path


__all__ = ["export_checkpoint_excel"]
