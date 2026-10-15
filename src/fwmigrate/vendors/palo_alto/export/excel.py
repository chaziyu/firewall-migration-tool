from __future__ import annotations

from itertools import chain
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Mapping

from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from ....source_reporting.options import ExcelExportProfile
from ....source_reporting.collection_excel import collection_summary, write_collection_evidence
from ....source_reporting.excel_style import append_report_row, excel_safe_value, style_fast_sheet, write_report_summary

from .excel_rows import ROW_BUILDERS, _PANExcelContext
from .excel_schema import SHEET_ORDER, HIDDEN_COLUMNS_BY_DEFAULT, SHEET_HEADERS
from ..source_report import PaloAltoSourceResult

_TITLE_FILL = PatternFill("solid", fgColor="17324D")
_HEADER_FILL = PatternFill("solid", fgColor="0F766E")
_TITLE_FONT = Font(color="FFFFFF", bold=True, size=14)
_WHITE_FONT = Font(color="FFFFFF", bold=True)
_MUTED_FONT = Font(color="64748B", italic=True)
_LINK_FONT = Font(color="0563C1", underline="single")
_TITLE_ALIGNMENT = Alignment(vertical="center")
_HEADER_ALIGNMENT = Alignment(wrap_text=True, vertical="center")
_BODY_ALIGNMENT = Alignment(wrap_text=True, vertical="top")
_LINK_ALIGNMENT = Alignment(horizontal="right")


def _excel_safe(value: Any) -> Any:
    return excel_safe_value(value)


def _add_back_link(sheet) -> None:
    if sheet.max_column > 1:
        cell = sheet.cell(2, sheet.max_column, "Back to Summary")
        cell.hyperlink = "#'Summary'!A1"
        cell.font = _LINK_FONT
        cell.alignment = _LINK_ALIGNMENT


def _write_table(workbook: Workbook, name: str, rows: Iterable[Mapping[str, Any]]) -> int:
    headers = SHEET_HEADERS[name]
    sheet = workbook.create_sheet(name)
    sheet.sheet_view.showGridLines = True
    sheet.sheet_view.zoomScale = 90
    max_column = max(len(headers), 1)
    sheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=max_column)
    title = sheet.cell(1, 1, name)
    title.fill, title.font = _TITLE_FILL, _TITLE_FONT
    title.alignment = _TITLE_ALIGNMENT
    sheet.row_dimensions[1].height = 24
    if max_column > 2:
        sheet.merge_cells(start_row=2, start_column=1, end_row=2, end_column=max_column - 1)
    note = sheet.cell(2, 1)
    note.font = _MUTED_FONT
    hidden_headers = set(HIDDEN_COLUMNS_BY_DEFAULT.get(name, ()))
    for column, header in enumerate(headers, 1):
        cell = sheet.cell(3, column, header)
        cell.alignment = _HEADER_ALIGNMENT
    row_count = 0
    for row_count, row in enumerate(rows, 1):
        sheet.append([_excel_safe(row.get(header)) for header in headers])
    note.value = f"{row_count} row(s). Analysis Status reports validation only; NO_VALIDATION_ISSUES does not imply complete extraction. Source Inventory reports extraction coverage."
    style_fast_sheet(sheet, header_row=3)
    sheet.freeze_panes = "D4" if name in {"Interfaces", "Security Policies", "NAT Rules"} else "C4" if len(headers) > 12 else "A4"
    for column, header in enumerate(headers, 1):
        if header in hidden_headers:
            sheet.column_dimensions[get_column_letter(column)].hidden = True
    _add_back_link(sheet)
    return row_count


def _write_summary(workbook: Workbook, context: _PANExcelContext, row_counts: Mapping[str, int]) -> None:
    sheet = workbook["Summary"] if "Summary" in workbook.sheetnames else workbook.create_sheet("Summary")
    coverage_sheets = {"Review Required", "Unresolved References", "Unsupported",
                       "PAN-OS Source Inventory", "Extraction Coverage", "PAN-OS Source Appendix"}
    write_report_summary(
        sheet, title="PAN-OS Configuration Report",
        metadata=(("Hostname", context.config.hostname), ("PAN-OS Version", context.config.source_version),
                  ("Scopes", "\n".join(context.derived.scope_identities) or None),
                  ("Source File", context.source_name)),
        profile="FAST" if workbook.write_only else "FULL",
        validation=(("Errors", len(context.validation.errors)),
                    ("Warnings", len(context.validation.warnings)),
                    ("Unresolved References", len(context.derived.unresolved_references))),
        inventory=((name, count, name) for name, count in row_counts.items()
                   if name not in coverage_sheets),
        coverage=(*collection_summary(context.collection_status),
                  *((name, count, name) for name, count in row_counts.items() if name in coverage_sheets),
                  ("Source Inventory Records", len(context.config.source_inventory)),
                  ("Extraction Issues", len(context.config.extraction_issues)),
                  *((f"{status.replace('_', ' ').title()} Records", sum(
                      value == status for values in context.domain_statuses.values() for value in values))
                    for status in ("PARTIAL", "SOURCE_ONLY", "UNSUPPORTED")),
                  ("Export Limitations", (
                      "FAST omits PAN-OS Source Inventory, Extraction Coverage, and PAN-OS Source Appendix. "
                      "Use FULL for complete source traceability." if workbook.write_only else
                      "FULL includes PAN-OS Source Inventory, Extraction Coverage, and PAN-OS Source Appendix."
                  ))),
    )


def _write_table_fast(workbook: Workbook, name: str, rows: Iterable[Mapping[str, Any]]) -> int:
    headers = SHEET_HEADERS[name]
    sheet = workbook.create_sheet(name)
    sheet.sheet_view.showGridLines = True
    sheet.freeze_panes = "D4" if name in {"Interfaces", "Security Policies", "NAT Rules"} else "C4" if len(headers) > 12 else "A4"
    for column, header in enumerate(headers, 1):
        dimension = sheet.column_dimensions[get_column_letter(column)]
        dimension.width = 28
        dimension.hidden = header in HIDDEN_COLUMNS_BY_DEFAULT.get(name, ())
    title = WriteOnlyCell(sheet, name)
    title.fill, title.font = _TITLE_FILL, _TITLE_FONT
    sheet.append([title])
    sheet.append(["FAST lightweight export. Analysis Status reports validation only; NO_VALIDATION_ISSUES does not imply complete extraction. Source Inventory reports extraction coverage. Source Inventory is available in FULL."])
    cells = []
    for header in headers:
        cell = WriteOnlyCell(sheet, header)
        cell.fill, cell.font = _HEADER_FILL, _WHITE_FONT
        cells.append(cell)
    sheet.append(cells)
    row_count = 0
    for row_count, row in enumerate(rows, 1):
        sheet.append([_excel_safe(row.get(header)) for header in headers])
    if row_count:
        sheet.auto_filter.ref = f"A3:{get_column_letter(len(headers))}{row_count + 3}"
    return row_count


def _build_fast_workbook(context: _PANExcelContext) -> Workbook:
    workbook = Workbook(write_only=True)
    workbook.create_sheet("Summary")
    counts = {}
    no_rows = object()
    for name in SHEET_ORDER:
        if name in {"Summary", "PAN-OS Source Inventory", "Extraction Coverage", "PAN-OS Source Appendix"}:
            continue
        rows = iter(ROW_BUILDERS[name](context))
        first = next(rows, no_rows)
        if first is no_rows and name != "Review Required":
            continue
        counts[name] = _write_table_fast(workbook, name, () if first is no_rows else chain((first,), rows))
    _write_summary(workbook, context, counts)
    return workbook


def export_panos_excel(
    analysis: PaloAltoSourceResult, output: BinaryIO | str | Path, *,
    source_name: str | None = None, profile: ExcelExportProfile | str = ExcelExportProfile.FULL,
    collection_status: str | None = None, collection_parts: Iterable[Mapping[str, Any]] = (),
    collection_warnings: Iterable[str] = (),
) -> None:
    profile = ExcelExportProfile(profile)
    context = _PANExcelContext(analysis, source_name, collection_status=collection_status)
    if profile is ExcelExportProfile.FAST:
        workbook = _build_fast_workbook(context)
    else:
        workbook = Workbook()
        workbook.remove(workbook.active)
        row_counts = {}
        for name in SHEET_ORDER:
            if name != "Summary":
                row_counts[name] = _write_table(workbook, name, ROW_BUILDERS[name](context))
        _write_summary(workbook, context, row_counts)
        workbook.move_sheet(workbook["Summary"], offset=-len(workbook.sheetnames) + 1)
    write_collection_evidence(workbook, collection_status, collection_parts, collection_warnings)
    if isinstance(output, (str, Path)):
        Path(output).parent.mkdir(parents=True, exist_ok=True)
    workbook.save(output)
