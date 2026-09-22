from __future__ import annotations

import ast
from io import BytesIO
from pathlib import Path

import pytest
from openpyxl import load_workbook

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.palo_alto.export.excel_schema import SHEET_HEADERS, SHEET_IMPLEMENTATION_STATUS


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def _workbook(name: str):
    reporter = PaloAltoSourceReporter()
    result = reporter.analyze_source((FIXTURES / name).read_text(encoding="utf-8"))
    output = BytesIO()
    reporter.export_excel(result, output, source_name=name)
    output.seek(0)
    return load_workbook(output, data_only=True)


@pytest.mark.parametrize("name", [
    "objects.xml", "services.xml", "schedules.xml", "policies.xml",
    "nat_pipeline_conformance.xml", "interfaces_extended.xml",
    "integrated_firewall.xml", "integrated_panorama.xml", "dynamic_routing.xml",
])
def test_supported_fixtures_export_real_workbooks(name):
    workbook = _workbook(name)
    assert workbook.sheetnames[0] == "Summary"
    assert "PAN-OS Source Inventory" in workbook.sheetnames
    assert "DHCP Servers" not in workbook.sheetnames
    assert workbook["Summary"]["B3"].value == name


def test_complete_schema_is_retained_while_unimplemented_sheets_are_omitted():
    workbook = _workbook("objects.xml")
    assert "DHCP Servers" in SHEET_HEADERS
    assert SHEET_IMPLEMENTATION_STATUS["DHCP Servers"] == "NOT_IMPLEMENTED"
    assert "DHCP Servers" not in workbook.sheetnames


def test_workbook_uses_fortigate_presentation_structure():
    workbook = _workbook("objects.xml")
    summary = workbook["Summary"]
    addresses = workbook["Addresses"]
    assert summary.merged_cells.ranges
    assert summary.freeze_panes == "A5"
    assert summary["A1"].fill.fgColor.rgb[-6:] == "17324D"
    assert summary["E3"].value == "Workbook navigation"
    assert addresses["A1"].value == "Addresses"
    assert addresses["A3"].value == "Name"
    assert addresses.freeze_panes == "A4"
    assert addresses.auto_filter.ref
    assert addresses.cell(2, addresses.max_column).value == "Back to Summary"


def test_source_and_derived_policy_order_are_separate():
    sheet = _workbook("policies.xml")["Security Policies"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    assert sheet.cell(4, headers["Source Order"]).value == 14
    assert sheet.cell(4, headers["Rulebase Position"]).value == "pre"
    assert sheet.cell(4, headers["Effective Order"]).value.endswith(": 1")


def test_interface_sheet_contains_topology_relationships():
    source = """<config><devices><entry name='fw'><network><interface>
      <ethernet><entry name='ethernet1/1'><layer3><aggregate-group>ae1</aggregate-group><units><entry name='ethernet1/1.10'/></units></layer3></entry></ethernet>
      <aggregate-ethernet><entry name='ae1'><layer3/></entry></aggregate-ethernet>
    </interface></network></entry></devices></config>"""
    reporter = PaloAltoSourceReporter()
    output = BytesIO()
    reporter.export_excel(reporter.analyze_source(source), output)
    sheet = load_workbook(BytesIO(output.getvalue()), data_only=True)["Interfaces"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    rows = {
        sheet.cell(row, headers["Name"]).value: row
        for row in range(4, sheet.max_row + 1)
        if sheet.cell(row, headers["Name"]).value
    }
    assert sheet.cell(rows["ethernet1/1"], headers["Aggregate Interface"]).value == "ae1"
    assert sheet.cell(rows["ethernet1/1.10"], headers["Parent Interface"]).value == "ethernet1/1"
    assert sheet.cell(rows["ethernet1/1.10"], headers["Topology Path"]).value.endswith("ethernet1/1, ae1")


def test_nat_rows_join_derived_values_by_full_source_identity():
    sheet = _workbook("nat_pipeline_conformance.xml")["NAT Rules"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    assert sheet.cell(4, headers["Derived Source Translation Mode"]).value == "PANDynamicIPAndPortTranslation"
    assert sheet.cell(6, headers["Derived Source Translation Mode"]).value == "PANStaticIPTranslation"
    assert sheet.cell(6, headers["Derived Destination Translation Mode"]).value == "PANDestinationTranslation"


def test_row_builders_do_not_reimplement_relationships_or_transforms():
    path = Path(__file__).parents[3] / "src" / "fwmigrate" / "vendors" / "palo_alto" / "export" / "excel_rows.py"
    calls = {node.func.id for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert calls.isdisjoint({"resolve_references", "build_policy_order", "build_scope_hierarchy", "transform_nat"})
