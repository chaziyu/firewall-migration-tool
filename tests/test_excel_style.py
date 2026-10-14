from io import BytesIO
from importlib import import_module
from pathlib import Path

import pytest
from openpyxl import Workbook, load_workbook

from fwmigrate.source_reporting.excel_style import (
    append_report_row, finish_report_workbook, style_fast_sheet, write_report_summary,
)


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


def test_report_row_neutralizes_formula_leading_source_values_in_full_and_streaming_workbooks():
    for write_only in (False, True):
        workbook = Workbook(write_only=write_only)
        sheet = workbook.create_sheet("Report") if write_only else workbook.active
        append_report_row(sheet, ("A", "B", "C", "D", "E"))
        append_report_row(sheet, ("=1+1", "+SUM(A1:A2)", "-2+3", "@cmd", "safe"))
        output = BytesIO()
        workbook.save(output)
        restored = load_workbook(BytesIO(output.getvalue()), read_only=True).active
        row = next(restored.iter_rows(min_row=2, max_row=2))
        assert [cell.value for cell in row] == ["'=1+1", "'+SUM(A1:A2)", "'-2+3", "'@cmd", "safe"]
        assert all(cell.data_type != "f" for cell in row)


@pytest.mark.parametrize("write_only", [False, True])
def test_summary_keeps_missing_metrics_safe_values_and_only_existing_links(write_only):
    workbook = Workbook(write_only=write_only)
    if not write_only:
        workbook.remove(workbook.active)
    summary = workbook.create_sheet("Summary")
    detail = workbook.create_sheet("Vendor's Objects")
    detail.column_dimensions["B"].hidden = True
    append_report_row(detail, ("Name", "Evidence"))
    append_report_row(detail, ("object", "retained"))
    write_report_summary(
        summary, title="Vendor Configuration Report", profile="FAST" if write_only else "FULL",
        metadata=(("Hostname", "=1+1"), ("Version", None), ("Scope", "shared")),
        validation=(("Errors", 0), ("Warnings", None), ("Unresolved References", None)),
        inventory=(("Objects", 0, detail.title), ("Unavailable", None, "Omitted")),
        coverage=(("Unknown", None), ("Source-only", 0, detail.title), ("Evidence", "+cmd")),
        indicators=(("Indicator", "@cmd"),),
    )
    finish_report_workbook(workbook)
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(BytesIO(output.getvalue()))
    summary = restored["Summary"]
    assert summary["B4"].value == "'=1+1"
    assert summary["D4"].value == "Not reported"
    assert summary["B7"].value == 0
    assert summary["D7"].value == "Not reported"
    objects = next(row for row in summary if row[0].value == "Objects")
    assert objects[1].value == 0
    assert objects[1].alignment.horizontal == "right"
    assert objects[2].hyperlink.target == "#'Vendor''s Objects'!A1"
    missing = next(row for row in summary if row[0].value == "Unavailable")
    assert missing[1].value == "Not reported"
    assert missing[2].hyperlink is None
    source_only = next(row for row in summary if row[0].value == "Source-only")
    assert source_only[2].hyperlink.target == "#'Vendor''s Objects'!A1"
    assert all(cell.data_type != "f" for row in summary for cell in row)
    assert not summary.auto_filter.ref
    assert summary.freeze_panes == "A5"
    assert summary.page_setup.fitToWidth == 1
    assert restored[detail.title].column_dimensions["B"].hidden
    assert [cell.value for cell in restored[detail.title][2]] == ["object", "retained"]


SUMMARY_CASES = (
    ("fortigate", "FortiGateSourceReporter", "fortigate/palo_alto_mvp.conf"),
    ("palo_alto", "PaloAltoSourceReporter", "palo_alto/integrated_panorama.xml"),
    ("cisco_asa", "CiscoASASourceReporter", "cisco_asa/nat_pipeline_conformance.txt"),
    ("cisco_ftd", "CiscoFTDSourceReporter", "cisco_ftd/fmc_selected_domains.json"),
    ("juniper_srx", "JuniperSRXSourceReporter", None),
    ("checkpoint", "CheckPointSourceReporter", "checkpoint/multidomain_full.json"),
)


@pytest.mark.parametrize("vendor,reporter_class,fixture", SUMMARY_CASES)
def test_vendor_summaries_share_sections_links_and_profile_counts(vendor, reporter_class, fixture):
    reporter = getattr(import_module(f"fwmigrate.vendors.{vendor}.source_report"), reporter_class)()
    source = ((Path(__file__).parent / "fixtures" / fixture).read_text(encoding="utf-8") if fixture else
              "set system host-name srx\nset interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\n"
              "set logical-systems branch interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24\n")
    analysis = reporter.analyze_source(source)
    inventories = []
    for profile in ("fast", "full"):
        output = BytesIO()
        reporter.export_excel(analysis, output, profile=profile)
        workbook = load_workbook(BytesIO(output.getvalue()))
        summary = workbook["Summary"]
        assert workbook.sheetnames[0] == "Summary"
        sections = [row[0].value for row in summary if row[0].value in {
            "SOURCE DETAILS", "VALIDATION", "CONFIGURATION INVENTORY", "SOURCE COVERAGE"}]
        assert sections == ["SOURCE DETAILS", "VALIDATION", "CONFIGURATION INVENTORY", "SOURCE COVERAGE"]
        assert not summary.auto_filter.ref
        assert summary["A1"].fill.fgColor.rgb.endswith("17324D")
        assert all(cell.value != "Workbook navigation" for row in summary for cell in row)
        inventory = []
        inside = False
        for row in summary:
            if row[0].value == "CONFIGURATION INVENTORY":
                inside = True
            elif row[0].value == "SOURCE COVERAGE":
                break
            elif inside and row[0].value != "Section":
                inventory.append((row[0].value, row[1].value))
                if row[2].hyperlink:
                    target = row[2].hyperlink.target[2:-4].replace("''", "'")
                    assert target in workbook.sheetnames
                    assert row[2].value == "Open"
        assert inventory
        inventories.append(dict(inventory))
    # FAST may omit empty PAN-OS sheets. Every retained count must match FULL.
    assert all(inventories[1][name] == count for name, count in inventories[0].items())
