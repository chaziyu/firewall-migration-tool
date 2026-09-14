import io

import pytest

openpyxl = pytest.importorskip("openpyxl")
from openpyxl import Workbook, load_workbook

from fwmigrate.ir.core import IRConfig, IRMetadata
from fwmigrate.report.excel_exporter import IRExcelExporter


def _exporter():
    return IRExcelExporter(
        IRConfig(
            metadata=IRMetadata(
                hostname="column-visibility-test",
                source_vendor="fortigate",
            )
        )
    )


def _workbook(source_vendor: str = "fortigate"):
    ir = IRConfig(
        metadata=IRMetadata(
            hostname="review-usability-test",
            source_vendor=source_vendor,
        )
    )
    return load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))


def _summary_navigation(workbook):
    summary = workbook["Summary"]
    header_row = next(
        row
        for row in range(1, summary.max_row + 1)
        if summary.cell(row, 1).value == "Category"
        and summary.cell(row, 2).value == "Sheet"
    )
    headers = {
        summary.cell(header_row, column).value: column
        for column in range(1, summary.max_column + 1)
        if summary.cell(header_row, column).value
    }

    navigation = {}
    for row in range(header_row + 1, summary.max_row + 1):
        sheet_name = summary.cell(row, headers["Sheet"]).value
        if not sheet_name:
            break
        navigation[sheet_name] = {
            header: summary.cell(row, column).value
            for header, column in headers.items()
        }

    return navigation


def _apply_view(sheet_name, headers, row):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = sheet_name
    sheet.append([sheet_name])
    sheet.append(["Inventory"])
    sheet.append(headers)
    sheet.append(row)
    _exporter()._apply_sheet_view(sheet)
    return sheet


def test_review_required_is_first_human_review_sheet():
    workbook = _workbook()

    assert workbook.sheetnames[0] == "Summary"
    assert workbook.sheetnames[1] == "Review Required"
    assert workbook.sheetnames[2] == "Extraction Evidence"
    assert workbook["Review Required"].sheet_state == "visible"
    assert workbook["Extraction Evidence"].sheet_state == "visible"
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


def test_summary_navigation_includes_hidden_applicable_sheets():
    workbook = _workbook()
    navigation = _summary_navigation(workbook)

    assert navigation["Review Required"]["Visibility"] == "Visible"
    assert navigation["Extraction Evidence"]["Visibility"] == "Visible"
    assert navigation["Interfaces"]["Visibility"] == "Hidden"
    assert navigation["Interface Secondary IPs"]["Visibility"] == "Hidden"
    assert navigation["Warnings"]["Visibility"] == "Visible"


def test_summary_has_key_counts_and_collapsed_hidden_navigation_rows():
    workbook = _workbook()
    summary = workbook["Summary"]

    assert summary["D4"].value == "Key Counts"

    hidden_grouped_rows = [
        row
        for row in range(1, summary.max_row + 1)
        if summary.row_dimensions[row].hidden
        and summary.row_dimensions[row].outlineLevel == 1
    ]
    assert hidden_grouped_rows


def test_hidden_detail_sheets_keep_parent_adjacency():
    workbook = _workbook()

    assert workbook["Interface Secondary IPs"].sheet_state == "hidden"
    assert (
        workbook.sheetnames.index("Interface Secondary IPs")
        == workbook.sheetnames.index("Interfaces") + 1
    )


def test_presentation_hiding_preserves_complete_fortigate_sheet_contract():
    workbook = _workbook()

    assert workbook.sheetnames == list(IRExcelExporter.SHEET_ORDER)
    assert workbook.sheetnames[:3] == [
        "Summary",
        "Review Required",
        "Extraction Evidence",
    ]


def test_core_sheet_reorders_core_and_review_then_groups_advanced_columns():
    sheet = _apply_view(
        "Addresses",
        (
            "Name",
            "Source UUID",
            "Type",
            "Value",
            "Migration Status",
            "Manual Review",
            "Additional Settings",
            "Description",
        ),
        (
            "server-1",
            "source-uuid",
            "ipmask",
            "10.0.0.10/32",
            "NORMALIZED",
            "No",
            '{"visibility":"still-preserved"}',
            "Application server",
        ),
    )

    headers = [sheet.cell(3, column).value for column in range(1, 9)]
    assert headers == [
        "Name",
        "Type",
        "Value",
        "Description",
        "Migration Status",
        "Manual Review",
        "Source UUID",
        "Additional Settings",
    ]

    for letter in "ABCDEF":
        assert sheet.column_dimensions[letter].hidden is False
        assert sheet.column_dimensions[letter].outlineLevel == 0

    for letter in "GH":
        assert sheet.column_dimensions[letter].hidden is True
        assert sheet.column_dimensions[letter].outlineLevel == 1

    # Advanced data is moved, not removed.
    assert sheet["G4"].value == "source-uuid"
    assert sheet["H4"].value == '{"visibility":"still-preserved"}'


def test_hidden_advanced_multiline_content_does_not_inflate_row_height():
    sheet = _apply_view(
        "Addresses",
        ("Name", "Type", "Value", "Additional Settings"),
        (
            "server-1",
            "ipmask",
            "10.0.0.10/32",
            "line1\nline2\nline3\nline4\nline5\nline6",
        ),
    )

    assert sheet.column_dimensions["D"].hidden is True
    assert sheet.row_dimensions[4].height == 20


def test_non_core_sheet_only_hides_columns_that_are_completely_empty():
    sheet = _apply_view(
        "Certificates",
        ("Name", "Issuer", "Unused Optional Field"),
        ("vpn-cert", "Example CA", None),
    )

    assert sheet.column_dimensions["A"].hidden is False
    assert sheet.column_dimensions["B"].hidden is False
    assert sheet.column_dimensions["C"].hidden is True


def test_extract_only_manual_rows_move_out_of_review_required():
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Source Inventory"
    sheet.append(["Source Inventory"])
    sheet.append(["Inventory"])
    sheet.append(["Name", "Migration Status", "Manual Review", "Review Reasons"])
    sheet.append(["raw-item", "EXTRACT_ONLY", "Yes", "Source-only evidence"])

    exporter = _exporter()
    assert exporter._review_rows(workbook) == []

    evidence = exporter._extraction_evidence_rows(workbook)
    assert len(evidence) == 1
    assert evidence[0][1] == "raw-item"
    assert evidence[0][3] == "Extract only"


def test_actionable_partial_status_stays_in_review_required():
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Policies"
    sheet.append(["Policies"])
    sheet.append(["Inventory"])
    sheet.append(["Name", "Extraction Status", "Manual Review", "Review Reasons"])
    sheet.append(["allow-web", "PARTIALLY_NORMALIZED", "Yes", "Check profile mapping"])

    rows = _exporter()._review_rows(workbook)
    assert len(rows) == 1
    assert rows[0][1] == "allow-web"
    assert rows[0][3] == "PARTIALLY_NORMALIZED"
