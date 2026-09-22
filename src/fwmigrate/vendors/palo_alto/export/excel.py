from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from .excel_rows import ROW_BUILDERS, _PANExcelContext
from .excel_schema import ACTIVE_SHEET_ORDER, DERIVED_COLUMNS_BY_SHEET, HIDDEN_COLUMNS_BY_DEFAULT, SHEET_HEADERS
from ..source_report import PaloAltoSourceResult

_TITLE_FILL = PatternFill("solid", fgColor="17324D")
_HEADER_FILL = PatternFill("solid", fgColor="0F766E")
_DERIVED_FILL = PatternFill("solid", fgColor="D7F0EC")
_REVIEW_FILL = PatternFill("solid", fgColor="FEF3C7")
_ERROR_FILL = PatternFill("solid", fgColor="FEE2E2")
_ALT_FILL = PatternFill("solid", fgColor="F8FAFC")
_TITLE_FONT = Font(color="FFFFFF", bold=True, size=14)
_HEADER_FONT = Font(color="FFFFFF", bold=True)
_WHITE_FONT = Font(color="FFFFFF", bold=True)
_MUTED_FONT = Font(color="64748B", italic=True)
_LINK_FONT = Font(color="0563C1", underline="single")
_BORDER = Border(bottom=Side(style="thin", color="CBD5E1"))


def _excel_safe(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _add_back_link(sheet) -> None:
    if sheet.max_column > 1:
        cell = sheet.cell(2, sheet.max_column, "Back to Summary")
        cell.hyperlink = "#'Summary'!A1"
        cell.font = _LINK_FONT
        cell.alignment = Alignment(horizontal="right")


def _widths(sheet, headers: Sequence[str]) -> None:
    for index, header in enumerate(headers, 1):
        name = header.lower()
        width = 36 if any(word in name for word in ("reason", "settings", "notes")) else 28 if any(word in name for word in ("description", "path", "value")) else 24 if any(word in name for word in ("members", "addresses", "references")) else 18
        sheet.column_dimensions[get_column_letter(index)].width = width


def _write_table(workbook: Workbook, name: str, rows: Sequence[Mapping[str, Any]]) -> None:
    headers = SHEET_HEADERS[name]
    sheet = workbook.create_sheet(name)
    sheet.sheet_view.showGridLines = False
    sheet.sheet_view.zoomScale = 90
    max_column = max(len(headers), 1)
    sheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=max_column)
    title = sheet.cell(1, 1, name)
    title.fill, title.font = _TITLE_FILL, _TITLE_FONT
    title.alignment = Alignment(vertical="center")
    sheet.row_dimensions[1].height = 24
    if max_column > 2:
        sheet.merge_cells(start_row=2, start_column=1, end_row=2, end_column=max_column - 1)
    sheet.cell(2, 1, f"{len(rows)} row(s). PAN-OS source values remain separate from derived and validation data.").font = _MUTED_FONT
    for column, header in enumerate(headers, 1):
        cell = sheet.cell(3, column, header)
        cell.fill, cell.font, cell.border = _HEADER_FILL, _HEADER_FONT, _BORDER
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    for row_number, row in enumerate(rows, 4):
        fill = _ERROR_FILL if row.get("__error__") else _REVIEW_FILL if row.get("__review__") else _ALT_FILL if row_number % 2 else None
        for column, header in enumerate(headers, 1):
            cell = sheet.cell(row_number, column, _excel_safe(row.get(header)))
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            if header in DERIVED_COLUMNS_BY_SHEET.get(name, ()):
                cell.fill = _DERIVED_FILL
            if fill is not None:
                cell.fill = fill
    if rows:
        sheet.auto_filter.ref = f"A3:{get_column_letter(max_column)}{len(rows) + 3}"
    sheet.freeze_panes = "D4" if name in {"Interfaces", "Security Policies", "NAT Rules"} else "C4" if len(headers) > 12 else "A4"
    _widths(sheet, headers)
    for column, header in enumerate(headers, 1):
        if header in HIDDEN_COLUMNS_BY_DEFAULT.get(name, ()):
            sheet.column_dimensions[get_column_letter(column)].hidden = True
    _add_back_link(sheet)


def _write_summary(workbook: Workbook, context: _PANExcelContext, row_counts: Mapping[str, int]) -> None:
    sheet = workbook.create_sheet("Summary")
    sheet.sheet_view.showGridLines = False
    sheet.freeze_panes = "A5"
    sheet.merge_cells("A1:F1")
    sheet["A1"], sheet["A1"].fill, sheet["A1"].font = "PAN-OS Configuration Report", _TITLE_FILL, Font(color="FFFFFF", bold=True, size=18)
    sheet["A1"].alignment = Alignment(vertical="center")
    sheet.row_dimensions[1].height = 30
    details = (("Source File", context.source_name), ("Hostname", context.config.hostname), ("PAN-OS Version", context.config.source_version),
               ("Scopes", "\n".join(_scope for _scope in context.derived.scope_identities)), ("Generated UTC", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
               ("Validation Errors", len(context.validation.errors)), ("Validation Warnings", len(context.validation.warnings)))
    for row, (label, value) in enumerate(details, 3):
        sheet.cell(row, 1, label).font = Font(bold=True)
        sheet.cell(row, 2, _excel_safe(value))
        sheet.cell(row, 2).alignment = Alignment(wrap_text=True, vertical="top")
    section_row = 11
    sheet.cell(section_row, 1, "Inventory")
    sheet.cell(section_row, 1).fill, sheet.cell(section_row, 1).font = _HEADER_FILL, _WHITE_FONT
    sheet.merge_cells(start_row=section_row, start_column=1, end_row=section_row, end_column=3)
    inventory = [name for name in ACTIVE_SHEET_ORDER if name not in {"Summary", "Review Required", "Validation", "Unresolved References", "Unsupported", "PAN-OS Source Inventory", "Extraction Coverage"}]
    for row, name in enumerate(inventory, section_row + 1):
        sheet.cell(row, 1, name)
        sheet.cell(row, 2, row_counts.get(name, 0))
        cell = sheet.cell(row, 3, "Open sheet")
        cell.hyperlink, cell.font = f"#'{name}'!A1", _LINK_FONT
    nav_column = 5
    sheet.cell(3, nav_column, "Workbook navigation")
    sheet.cell(3, nav_column).fill, sheet.cell(3, nav_column).font = _HEADER_FILL, _WHITE_FONT
    for row, name in enumerate((item for item in ACTIVE_SHEET_ORDER if item != "Summary"), 4):
        cell = sheet.cell(row, nav_column, name)
        cell.hyperlink, cell.font = f"#'{name}'!A1", _LINK_FONT
    sheet.column_dimensions["A"].width = 28
    sheet.column_dimensions["B"].width = 24
    sheet.column_dimensions["C"].width = 16
    sheet.column_dimensions["E"].width = 34


def export_panos_excel(analysis: PaloAltoSourceResult, output: BinaryIO | str | Path, *, source_name: str | None = None) -> None:
    context = _PANExcelContext(analysis, source_name)
    rows_by_sheet = {name: ROW_BUILDERS[name](context) for name in ACTIVE_SHEET_ORDER if name != "Summary"}
    workbook = Workbook()
    workbook.remove(workbook.active)
    _write_summary(workbook, context, {name: len(rows) for name, rows in rows_by_sheet.items()})
    for name, rows in rows_by_sheet.items():
        _write_table(workbook, name, rows)
    if isinstance(output, (str, Path)):
        Path(output).parent.mkdir(parents=True, exist_ok=True)
    workbook.save(output)
