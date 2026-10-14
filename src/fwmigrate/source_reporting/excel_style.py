"""Lightweight presentation shared by vendor-native Excel reports."""

from openpyxl.cell import WriteOnlyCell
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

_HEADER_FILL = PatternFill("solid", fgColor="0F766E")
_HEADER_FONT = Font(color="FFFFFF", bold=True, size=10)
_TITLE_FILL = PatternFill("solid", fgColor="17324D")
_TITLE_FONT = Font(color="FFFFFF", bold=True, size=14)


def _safe_cell_value(value):
    """Prevent untrusted source strings from being interpreted as Excel formulas."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def style_fast_sheet(sheet, *, header_row: int = 1) -> None:
    """Style headers only; leave body cells on Excel's native grid."""
    sheet.sheet_view.showGridLines = True
    sheet.sheet_format.defaultColWidth = 28
    for column in range(1, sheet.max_column + 1):
        letter = get_column_letter(column)
        sheet.column_dimensions[letter].width = 28
        cell = sheet.cell(header_row, column)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
    sheet.freeze_panes = f"A{header_row + 1}"
    sheet.auto_filter.ref = f"A{header_row}:{get_column_letter(sheet.max_column)}{sheet.max_row}"


def append_report_row(sheet, values) -> None:
    """Append vendor-owned values to either a normal or streaming worksheet."""
    values = tuple(_safe_cell_value(value) for value in values)
    if not sheet.parent.write_only:
        sheet.append(values)
        return
    count = getattr(sheet, "_report_row_count", 0)
    if count == 0:
        values = tuple(values)
        sheet._report_column_count = len(values)
        sheet.sheet_view.showGridLines = True
        sheet.sheet_format.defaultColWidth = 28
        sheet.freeze_panes = "A3" if getattr(sheet, "_report_title_written", False) else "A2"
        cells = []
        for column, value in enumerate(values, 1):
            sheet.column_dimensions[get_column_letter(column)].width = 28
            cell = WriteOnlyCell(sheet, value)
            cell.fill, cell.font = _HEADER_FILL, _HEADER_FONT
            cells.append(cell)
        sheet.append(cells)
    else:
        sheet.append(values)
    sheet._report_row_count = count + 1


def append_report_title(sheet, title: str) -> None:
    """Add the FortiGate-style title band to a streaming report sheet."""
    if not sheet.parent.write_only:
        raise ValueError("append_report_title requires a write-only worksheet")
    sheet.sheet_view.showGridLines = True
    sheet.sheet_format.defaultColWidth = 28
    sheet.freeze_panes = "A3"
    cells = []
    for column in range(1, 7):
        sheet.column_dimensions[get_column_letter(column)].width = 28
        cell = WriteOnlyCell(sheet, title if column == 1 else None)
        cell.fill, cell.font = _TITLE_FILL, _TITLE_FONT
        cells.append(cell)
    sheet.append(cells)
    sheet._report_title_written = True


def append_report_navigation(workbook, *, column: int = 5) -> None:
    """Append sheet links below a streaming summary."""
    summary = workbook["Summary"]
    summary.column_dimensions[get_column_letter(column)].width = 34
    header = WriteOnlyCell(summary, "Workbook navigation")
    header.fill, header.font = _HEADER_FILL, _HEADER_FONT
    summary.append([None] * (column - 1) + [header])
    for sheet in workbook.worksheets:
        if sheet is summary:
            continue
        cell = WriteOnlyCell(summary, sheet.title)
        cell.hyperlink = f"#'{sheet.title}'!A1"
        cell.font = Font(color="0563C1", underline="single")
        summary.append([None] * (column - 1) + [cell])


def finish_report_workbook(workbook, *, summary_title: str | None = None) -> None:
    """Finalize FAST filters or FULL headers and workbook navigation."""
    if workbook.write_only:
        append_report_navigation(workbook)
        for sheet in workbook.worksheets:
            first_row = 2 if getattr(sheet, "_report_title_written", False) else 1
            sheet.auto_filter.ref = (
                f"A{first_row}:{get_column_letter(sheet._report_column_count)}{sheet._report_row_count + first_row - 1}"
            )
        return
    if summary_title:
        summary = workbook["Summary"]
        summary.insert_rows(1)
        summary.merge_cells(start_row=1, start_column=1, end_row=1, end_column=6)
        summary.cell(1, 1, summary_title)
        summary.cell(1, 1).fill = _TITLE_FILL
        summary.cell(1, 1).font = _TITLE_FONT
        summary.row_dimensions[1].height = 30
        summary.freeze_panes = "A3"
        summary.sheet_view.showGridLines = True
        for column in range(1, 7):
            summary.column_dimensions[get_column_letter(column)].width = 28
    summary = workbook["Summary"]
    for sheet in workbook.worksheets:
        style_fast_sheet(sheet, header_row=2 if sheet is summary and summary_title else 1)
    if summary_title:
        for column in range(1, summary.max_column + 1):
            cell = summary.cell(2, column)
            cell.fill, cell.font = _HEADER_FILL, _HEADER_FONT
        summary.freeze_panes = "A3"
        summary.column_dimensions["A"].width = 34
        summary.column_dimensions["B"].width = 34
        summary.column_dimensions["E"].width = 34
        nav_header = summary.cell(3, 5, "Workbook navigation")
        nav_header.fill, nav_header.font = _HEADER_FILL, _HEADER_FONT
        nav_row = 4
    else:
        summary.append(())
        summary.append(("Workbook navigation",))
        nav_row = summary.max_row
    for sheet in workbook.worksheets:
        if sheet is summary:
            continue
        cell = summary.cell(nav_row, 5 if summary_title else 1, sheet.title)
        cell.hyperlink = f"#'{sheet.title}'!A1"
        cell.font = Font(color="0563C1", underline="single")
        sheet.cell(1, 1).hyperlink = "#'Summary'!A1"
        nav_row += 1
