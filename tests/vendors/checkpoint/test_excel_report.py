import io
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_excel_report_contains_traceability_sheets():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    output = io.BytesIO()
    from fwmigrate.vendors.checkpoint.export.excel import export_checkpoint_excel
    export_checkpoint_excel(extract_checkpoint_source(source), output)
    assert {"Collection", "Validation"}.issubset(load_workbook(io.BytesIO(output.getvalue()), read_only=True).sheetnames)
    assert extract_checkpoint_source(source).config.hosts
