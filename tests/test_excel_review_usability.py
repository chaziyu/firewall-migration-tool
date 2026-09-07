import io

import pytest

openpyxl = pytest.importorskip("openpyxl")
from openpyxl import load_workbook

from fwmigrate.ir.core import IRConfig, IRMetadata
from fwmigrate.report.excel_exporter import IRExcelExporter


def _workbook(source_vendor: str = "fortigate"):
    ir = IRConfig(
        metadata=IRMetadata(
            hostname="review-usability-test",
            source_vendor=source_vendor,
        )
    )
    return load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))


def test_review_required_is_first_human_review_sheet():
    workbook = _workbook()

    assert workbook.sheetnames[0] == "Summary"
    assert workbook.sheetnames[1] == "Review Required"
    assert workbook["Review Required"].sheet_state == "visible"
    assert workbook["Review Required"].freeze_panes == "B4"


def test_zero_record_inventory_sheets_are_retained_but_hidden():
    workbook = _workbook()

    assert "Interfaces" in workbook.sheetnames
    assert workbook["Interfaces"].sheet_state == "hidden"

    # Audit evidence remains directly visible even when there are no findings.
    assert workbook["Warnings"].sheet_state == "visible"
    assert workbook["Unsupported"].sheet_state == "visible"
    assert workbook["Unresolved References"].sheet_state == "visible"
    assert workbook["Extraction Coverage"].sheet_state == "visible"


def test_detail_evidence_is_retained_but_hidden_by_default():
    workbook = _workbook()

    assert "FortiGate Source Configuration" in workbook.sheetnames
    assert workbook["FortiGate Source Configuration"].sheet_state == "hidden"


def test_summary_navigation_excludes_hidden_zero_record_sheets():
    workbook = _workbook()
    summary = workbook["Summary"]

    navigation_sheet_names = {
        summary.cell(row, 2).value
        for row in range(1, summary.max_row + 1)
        if summary.cell(row, 2).value
    }

    assert "Review Required" in navigation_sheet_names
    assert "Interfaces" not in navigation_sheet_names
