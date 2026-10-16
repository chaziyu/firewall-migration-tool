"""Lightweight presentation shared by vendor-native Excel reports."""

from openpyxl.cell import WriteOnlyCell
from datetime import datetime, timezone
from textwrap import wrap

from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

_HEADER_FILL = PatternFill("solid", fgColor="0F766E")
_HEADER_FONT = Font(color="FFFFFF", bold=True, size=10)
_TITLE_FILL = PatternFill("solid", fgColor="17324D")
_TITLE_FONT = Font(color="FFFFFF", bold=True, size=14)
_HEADER_ALIGNMENT = Alignment(wrap_text=True, vertical="center")
_HEADER_BORDER = Border(bottom=Side(style="thin", color="D9E2DF"))


def style_report_header(cell) -> None:
    """Use the same compact header in native and streaming vendor worksheets."""
    cell.fill, cell.font, cell.alignment = _HEADER_FILL, _HEADER_FONT, _HEADER_ALIGNMENT
    cell.border = _HEADER_BORDER


def report_column_width(header) -> int:
    """Bound widths using labels only, without scanning or styling source rows."""
    words = str(header).lower().replace("_", " ").split()
    if any(word in words for word in ("description", "comments", "notes", "settings", "reasons", "members", "addresses", "value")):
        return 44
    if words and (words[-1] in {"id", "count", "port", "vlan", "enabled"} or words == ["vdom"]):
        return 16
    return 28


def write_report_summary(
    sheet, *, title, metadata, profile, validation, inventory, coverage=(), indicators=(),
) -> None:
    """Present vendor-owned metrics without inferring source state or sheet availability."""
    sheet._report_summary_written = True
    sheet.sheet_view.showGridLines = False
    sheet.sheet_view.zoomScale = 90
    sheet.freeze_panes = "A5"
    sheet.sheet_properties.pageSetUpPr.fitToPage = True
    sheet.page_setup.orientation = "landscape"
    sheet.page_setup.paperSize = Worksheet.PAPERSIZE_A4
    sheet.page_setup.fitToWidth, sheet.page_setup.fitToHeight = 1, 0
    sheet.print_options.horizontalCentered = True
    for column, width in zip("ABCDEF", (38, 32, 28, 32, 28, 32)):
        sheet.column_dimensions[column].width = width
    separator = Border(bottom=Side(style="hair", color="E2E8F0"))
    label_font = Font(bold=True, color="334155")
    section_fill = PatternFill("solid", fgColor="EEF2F6")
    row_number = 0

    def append(values, *, heading=False, title_band=False, labels=(), link=None):
        nonlocal row_number
        row_number += 1
        # Streaming row dimensions must be set before appending the row.
        lines = 1
        for index, value in enumerate(values):
            width = int(sheet.column_dimensions[get_column_letter(index + 1)].width) - 2
            lines = max(lines, sum(max(1, len(wrap(line, width=width))) for line in str(value).split("\n")))
        sheet.row_dimensions[row_number].height = 30 if title_band else 24 if heading else min(409, max(32, lines * 15 + 8))
        cells = []
        for index, value in enumerate((*values, *([None] * (6 - len(values))))):
            value = "Not reported" if value is None and index < len(values) else value
            cell = WriteOnlyCell(sheet, excel_safe_value(value))
            cell.row, cell.column = row_number, index + 1
            cell.alignment = Alignment(
                vertical="center", wrap_text=not title_band,
                horizontal="right" if isinstance(value, (int, float)) else "left",
                indent=1 if not heading and not title_band and (index in labels or link and index == 2) else 0,
            )
            if isinstance(value, int) and not isinstance(value, bool):
                cell.number_format = "#,##0"
            if title_band:
                cell.fill, cell.font = _TITLE_FILL, _TITLE_FONT
            elif heading:
                cell.fill, cell.font = section_fill, label_font
            else:
                cell.border = separator
                if index in labels:
                    cell.font = label_font
            if link and index == 2:
                target = link.replace("'", "''")
                cell.hyperlink = f"#'{target}'!A1"
                cell.font = Font(color="0563C1", underline="single")
            cells.append(cell)
        sheet.append(cells)

    def pairs(values):
        values = tuple(values)
        for start in range(0, len(values), 3):
            append([value for pair in values[start:start + 3] for value in pair], labels=(0, 2, 4))

    append([title], title_band=True)
    sheet.append(())
    row_number += 1
    append(["SOURCE DETAILS"], heading=True)
    pairs((*metadata, ("Export Profile", profile),
           ("Generated UTC", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))))
    append(["VALIDATION"], heading=True)
    pairs(validation)
    append(["CONFIGURATION INVENTORY"], heading=True)
    append(["Section", "Count", "Sheet"], heading=True)
    for label, count, target in inventory:
        available = target in sheet.parent.sheetnames if target else False
        append([label, count, "Open" if available else "Not exported"], labels=(0,),
               link=target if available else None)
    append(["SOURCE COVERAGE"], heading=True)
    for label, value, *target in coverage:
        link = target[0] if target and target[0] in sheet.parent.sheetnames else None
        append([label, value, "Open"] if link else [label, value], labels=(0,), link=link)
    if indicators:
        append(["MIGRATION INDICATORS"], heading=True)
        for label, value in indicators:
            append([label, value], labels=(0,))
    sheet.print_area = f"A1:F{row_number}"


def excel_safe_value(value):
    """Prevent untrusted source strings from being interpreted as Excel formulas."""
    if isinstance(value, str) and (
        value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n"))
    ):
        return "'" + value
    return value


def style_fast_sheet(sheet, *, header_row: int = 1) -> None:
    """Style headers only; leave body cells on Excel's native grid."""
    sheet.sheet_view.showGridLines = True
    sheet.sheet_view.zoomScale = 90
    sheet.sheet_format.defaultColWidth = 28
    sheet.sheet_format.defaultRowHeight = 18
    sheet.row_dimensions[header_row].height = 30
    for column in range(1, sheet.max_column + 1):
        letter = get_column_letter(column)
        cell = sheet.cell(header_row, column)
        dimension = sheet.column_dimensions[letter]
        if dimension.width == 13:
            dimension.width = report_column_width(cell.value)
        style_report_header(cell)
    sheet.freeze_panes = f"A{header_row + 1}"
    sheet.auto_filter.ref = f"A{header_row}:{get_column_letter(sheet.max_column)}{sheet.max_row}"


def append_report_row(sheet, values) -> None:
    """Append vendor-owned values to either a normal or streaming worksheet."""
    values = tuple(excel_safe_value(value) for value in values)
    count = getattr(sheet, "_report_row_count", 0)
    if not sheet.parent.write_only:
        sheet.append(values)
        sheet._report_row_count = count + 1
        return
    if count == 0:
        values = tuple(values)
        sheet._report_column_count = len(values)
        sheet.sheet_view.showGridLines = True
        sheet.sheet_view.zoomScale = 90
        sheet.sheet_format.defaultColWidth = 28
        sheet.sheet_format.defaultRowHeight = 18
        sheet.row_dimensions[1].height = 30
        sheet.freeze_panes = "A2"
        cells = []
        for column, value in enumerate(values, 1):
            dimension = sheet.column_dimensions[get_column_letter(column)]
            if dimension.width == 13:
                dimension.width = report_column_width(value)
            cell = WriteOnlyCell(sheet, value)
            style_report_header(cell)
            cells.append(cell)
        sheet.append(cells)
    else:
        sheet.append(values)
    sheet._report_row_count = count + 1


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
    """Finalize details; summary_title applies only to legacy summaries.

    Modern summaries get their title from write_report_summary, including streaming exports.
    """
    if getattr(workbook["Summary"], "_report_summary_written", False):
        for sheet in workbook.worksheets:
            if sheet.title == "Summary":
                continue
            if workbook.write_only:
                first_row = 1
                sheet.auto_filter.ref = (
                    f"A{first_row}:{get_column_letter(sheet._report_column_count)}"
                    f"{sheet._report_row_count + first_row - 1}"
                )
            else:
                style_fast_sheet(sheet)
                sheet.cell(1, 1).hyperlink = "#'Summary'!A1"
        return
    if workbook.write_only:
        append_report_navigation(workbook)
        for sheet in workbook.worksheets:
            if sheet.title == "Summary":
                continue
            first_row = 1
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
