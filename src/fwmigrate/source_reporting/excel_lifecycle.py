"""Own report workbooks and their streaming XML resources for one export."""

from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from openpyxl.writer.excel import ExcelWriter
from openpyxl.drawing.spreadsheet_drawing import SpreadsheetDrawing
from openpyxl.worksheet._writer import WorksheetWriter


@contextmanager
def report_workbook(workbook):
    """Clean up this workbook even when building or saving a sheet fails.

    openpyxl 3.1's Workbook.close() only closes read-only archives. Write-only
    sheets own generators and temporary XML files until a successful save.
    Keep that version-specific lifecycle here; never touch another export's files.
    """
    try:
        yield workbook
    finally:
        for sheet in workbook.worksheets:
            writer = getattr(sheet, "_writer", None)
            if writer is None:
                continue
            if workbook.write_only and not sheet.closed:
                with suppress(Exception):
                    sheet.close()
            with suppress(Exception):
                writer.close()
            if isinstance(writer.out, str) and Path(writer.out).exists():
                writer.cleanup()
        workbook.close()


def save_report_workbook(workbook, output):
    """Close the ZIP archive on failed saves without closing caller-owned output."""
    workbook.properties.modified = datetime.now(timezone.utc).replace(tzinfo=None)
    with ZipFile(output, "w", ZIP_DEFLATED, allowZip64=True) as archive:
        _ReportExcelWriter(workbook, archive).save()


class _ReportExcelWriter(ExcelWriter):
    def write_worksheet(self, sheet):
        if self.workbook.write_only:
            return super().write_worksheet(sheet)
        # openpyxl's normal writer also owns a temporary XML file, but does not
        # attach it to the worksheet. Register it before write(), which can fail.
        # Preserve the 3.1 writer's drawing, relationship and manifest handling.
        sheet._drawing = SpreadsheetDrawing()
        sheet._drawing.charts = sheet._charts
        sheet._drawing.images = sheet._images
        writer = WorksheetWriter(sheet)
        sheet._writer = writer
        writer.write()
        sheet._rels = writer._rels
        self._archive.write(writer.out, sheet.path[1:])
        self.manifest.append(sheet)
        writer.cleanup()
