from __future__ import annotations

from pathlib import Path
from typing import Any, BinaryIO

from openpyxl import Workbook

from .excel_rows import domain_items, rows_for
from .excel_schema import SHEET_HEADERS, SHEET_ORDER
from ..source_report import PaloAltoSourceResult


def _safe(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple, set)):
        return "\n".join(f"{key}: {value[key]}" for key in value) if isinstance(value, dict) else "\n".join(map(str, value))
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _write(sheet, rows):
    for row in rows:
        sheet.append([_safe(value) for value in row])


def export_panos_excel(analysis: PaloAltoSourceResult, output: BinaryIO | str | Path) -> None:
    workbook = Workbook()
    workbook.remove(workbook.active)
    config, derived = analysis.config, analysis.derived
    items = domain_items(analysis)
    for sheet_name in SHEET_ORDER:
        sheet = workbook.create_sheet(sheet_name)
        headers = SHEET_HEADERS[sheet_name]
        if headers:
            sheet.append(list(headers))
        if sheet_name == "Summary":
            _write(sheet, [["Hostname", config.hostname], ["Source Version", config.source_version],
                           ["Scopes", len(config.scopes)], ["Source Records", len(config.source_inventory)],
                           ["Validation Errors", len(analysis.validation.errors)],
                           ["Validation Warnings", len(analysis.validation.warnings)]])
        elif sheet_name in items:
            _write(sheet, rows_for(items[sheet_name], headers, analysis))
        elif sheet_name == "Unresolved References":
            _write(sheet, [[item.source_scope.kind if item.source_scope else None,
                            item.source_scope.name if item.source_scope else None, item.expected_family,
                            item.owner_name, item.owner_field, item.reference_name, item.expected_family,
                            item.resolution_reason] for item in derived.reference_resolutions if item.status != "RESOLVED"])
        elif sheet_name == "Validation":
            _write(sheet, [[issue.severity, issue.domain, issue.source_name, None, None, issue.field, issue.message, None]
                           for issue in analysis.validation.issues])
        elif sheet_name == "PAN-OS Source Inventory":
            _write(sheet, [[r.scope.kind if r.scope else None, r.scope.name if r.scope else None, None,
                            r.source_path, r.kind, r.name, None, None, None, r.values,
                            "UNSUPPORTED" if r.unsupported else "EXTRACTED"] for r in config.source_inventory])
        elif sheet_name == "Unsupported":
            _write(sheet, [[None, None, path, 1, "UNSUPPORTED", "source-only evidence", path]
                           for path in config.unknown_paths])
    if isinstance(output, (str, Path)):
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        workbook.save(output)
    else:
        workbook.save(output)
