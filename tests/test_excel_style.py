from io import BytesIO

from openpyxl import Workbook, load_workbook

from fwmigrate.source_reporting.excel_style import style_fast_sheet


def test_fast_style_preserves_native_cells_and_hidden_evidence_after_save():
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(("Name", "Additional Settings"))
    sheet.append(("source object", "retained evidence"))
    sheet.column_dimensions["B"].hidden = True
    style_fast_sheet(sheet)
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(BytesIO(output.getvalue())).active
    assert restored.sheet_view.showGridLines
    assert restored.freeze_panes == "A2"
    assert restored.auto_filter.ref == "A1:B2"
    assert restored.column_dimensions["B"].hidden
    assert restored.column_dimensions["A"].width == restored.column_dimensions["B"].width == 28
    assert restored["A1"].fill.fgColor.rgb.endswith("0F766E")
    assert [cell.value for cell in restored[2]] == ["source object", "retained evidence"]
    assert all(not cell.has_style for cell in restored[2])
