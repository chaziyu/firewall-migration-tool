from io import BytesIO
from importlib import import_module
from pathlib import Path
from dataclasses import replace

import pytest
from openpyxl import Workbook, load_workbook

from fwmigrate.source_reporting.excel_style import (
    append_report_row, excel_safe_value, finish_report_workbook, style_fast_sheet, write_report_summary,
)


@pytest.mark.parametrize("write_only", [False, True])
def test_readable_business_rows_keep_values_and_hidden_cells_without_restyling_scalars(write_only):
    from fwmigrate.source_reporting.excel_style import readable_report_row

    workbook = Workbook(write_only=write_only)
    sheet = workbook.create_sheet("Business") if write_only else workbook.active
    sheet.column_dimensions["A"].width = 20
    sheet.column_dimensions["B"].width = 24
    sheet.column_dimensions["C"].hidden = True
    long = "first address\nsecond address\nthird address"
    hidden = "hidden technical evidence " * 100
    sheet.append(readable_report_row(sheet, 1, [0, long, hidden, False]))
    sheet.append(readable_report_row(sheet, 2, [1, "short", None, False]))
    sheet.append(readable_report_row(sheet, 3, [2, "many\n" * 500, None, False]))
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(output).active
    assert [cell.value for cell in restored[1]] == [0, long, hidden, False]
    assert restored["B1"].alignment.wrap_text and restored["B1"].alignment.vertical == "top"
    assert 49 <= restored.row_dimensions[1].height <= 409
    assert restored.row_dimensions[3].height == 409
    assert not restored["C1"].has_style
    assert all(not cell.has_style for cell in restored[2])


@pytest.mark.parametrize('write_only', [False, True])
def test_xml_unsafe_text_is_visible_and_formula_protection_is_idempotent(write_only):
    value = '=é\x00\x01\x0b\x0c\x1f\ufffe\uffff\ud800\t\r\n漢字😀'
    expected = "'=é\\u0000\\u0001\\u000b\\u000c\\u001f\\ufffe\\uffff\\ud800\t\r\n漢字😀"
    assert excel_safe_value(value) == expected
    assert excel_safe_value(expected) == expected
    workbook = Workbook(write_only=write_only)
    sheet = workbook.create_sheet('Report') if write_only else workbook.active
    append_report_row(sheet, ['Evidence'])
    append_report_row(sheet, [value])
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(output)
    assert restored.active['A2'].value in (expected, expected.replace('\r\n', '\n'))
    assert restored.active['A2'].data_type == 's'


@pytest.mark.parametrize('write_only', [False, True])
@pytest.mark.parametrize('value', ['x' * 32767, 'x' * 32768, 'x' * 32767 + '=1+1',
                                 '=1+1' + '\x01' * 12000],
                         ids=['boundary', 'overflow', 'formula-chunk', 'escaped-overflow'])
def test_overflow_preserves_sanitized_text_and_formula_safe_chunks(write_only, value):
    workbook = Workbook(write_only=write_only)
    if not write_only:
        workbook.remove(workbook.active)
    summary = workbook.create_sheet('Summary')
    detail = workbook.create_sheet('Evidence')
    append_report_row(detail, ['Value', 'Repeated'])
    append_report_row(detail, [value, value])
    write_report_summary(summary, title='Report', metadata=[('Long source', value)], profile='FULL',
                         validation=[], inventory=[])
    finish_report_workbook(workbook)
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(output)
    expected = excel_safe_value(value)
    if len(expected) <= 32767:
        assert 'Text Overflow' not in restored.sheetnames
        assert restored['Evidence']['A2'].value == expected
        return
    overflow = restored['Text Overflow']
    for sheet_name, coordinate in [('Evidence', 'A2'), ('Evidence', 'B2'), ('Summary', 'B4')]:
        rows = [row for row in list(overflow.values)[1:] if row[:2] == (sheet_name, coordinate)]
        assert [row[2] for row in rows] == list(range(1, len(rows) + 1))
        assert all(row[3] == len(rows) for row in rows)
        assert ''.join(row[4] for row in rows) == expected
        assert restored[sheet_name][coordinate].value.startswith('See Text Overflow:')
    assert all(cell.data_type != 'f' for row in overflow for cell in row)
    assert all(len(str(cell.value or '')) <= 32767 for row in overflow for cell in row)


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
    assert restored.column_dimensions["A"].width == 28
    assert restored.column_dimensions["B"].width == 44
    assert restored.row_dimensions[1].height == 30
    assert restored["A1"].alignment.wrap_text
    assert restored["A1"].fill.fgColor.rgb.endswith("0F766E")
    assert [cell.value for cell in restored[2]] == ["source object", "retained evidence"]
    assert all(not cell.has_style for cell in restored[2])


def test_report_row_neutralizes_formula_leading_source_values_in_full_and_streaming_workbooks():
    for write_only in (False, True):
        workbook = Workbook(write_only=write_only)
        sheet = workbook.create_sheet("Report") if write_only else workbook.active
        values = ("=1+1", "+SUM(A1:A2)", "-2+3", "@cmd", "\t=1+1", "\r=1+1", "\n=1+1",
                  "  =1+1", " \t@cmd", "  +cmd", "  -cmd", "safe", 0, -2, False, None)
        append_report_row(sheet, tuple(str(index) for index in range(len(values))))
        append_report_row(sheet, values)
        output = BytesIO()
        workbook.save(output)
        restored = load_workbook(BytesIO(output.getvalue()), read_only=True).active
        row = next(restored.iter_rows(min_row=2, max_row=2, max_col=len(values)))
        actual = [cell.value for cell in row]
        expected = ["'" + value for value in values[:11]] + list(values[11:])
        assert actual[:5] == expected[:5]
        assert actual[5] in ("'\r=1+1", "'\n=1+1")
        assert actual[6:] == expected[6:]
        assert all(cell.data_type != "f" for cell in row)


@pytest.mark.parametrize("write_only", [False, True])
def test_shared_dimensions_preserve_explicit_widths_and_unstyled_source_cells(write_only):
    workbook = Workbook(write_only=write_only)
    sheet = workbook.create_sheet("Objects") if write_only else workbook.active
    sheet.column_dimensions["B"].width = 37
    sheet.column_dimensions["D"].hidden = True
    append_report_row(sheet, ("Rule ID", "Name", "Description", "Additional Settings"))
    append_report_row(sheet, (0, False, "long technical value " * 100, "'=literal"))
    if not write_only:
        style_fast_sheet(sheet)
    else:
        sheet.auto_filter.ref = "A1:D2"
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(output).active
    assert [restored.column_dimensions[key].width for key in "ABCD"] == [16, 37, 44, 44]
    assert restored.column_dimensions["D"].hidden
    assert restored.freeze_panes == "A2"
    assert restored.auto_filter.ref == "A1:D2"
    assert restored.sheet_format.defaultRowHeight == 18
    assert restored.row_dimensions[1].height == 30
    assert restored["A1"].font.sz == 10
    assert restored["A1"].alignment.wrap_text
    assert [cell.value for cell in restored[2]] == [0, False, "long technical value " * 100, "'=literal"]
    assert all(not cell.has_style for cell in restored[2])


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-cmd", "@cmd", "\t=1+1", "\r=1+1", "\n=1+1",
                                   "  =1+1", " \t@cmd", "  +cmd", "  -cmd", "  '=escaped",
                                   "'=already escaped", "safe", "|plain text", "", 0, -2, 1.5, False, None])
def test_vendor_excel_guards_use_shared_policy_without_double_escaping(value):
    converters = (
        ("fortigate.export.excel_common", "_excel_safe"),
        ("palo_alto.export.excel", "_excel_safe"),
    )
    expected = excel_safe_value(value)
    assert excel_safe_value(expected) == expected
    for module, name in converters:
        convert = getattr(import_module(f"fwmigrate.vendors.{module}"), name)
        # FortiGate deliberately presents explicit boolean source values as Yes/No.
        converted = "No" if module.startswith("fortigate") and value is False else expected
        assert convert(value) == converted


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
        metadata=(("Hostname", "\t=1+1"), ("Version", None), ("Scope", "shared")),
        validation=(("Errors", 0), ("Warnings", None), ("Unresolved References", None)),
        inventory=(("Objects", 0, detail.title), ("Unavailable", None, "Omitted")),
        coverage=(("Unknown", None), ("Source-only", 0, detail.title), ("Evidence", "+cmd")),
        indicators=(("Indicator", "@cmd"),),
    )
    finish_report_workbook(workbook, summary_title="Legacy title does not replace a modern summary")
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(BytesIO(output.getvalue()))
    summary = restored["Summary"]
    assert summary["A1"].value == "Vendor Configuration Report"
    assert summary["B4"].value == "'\t=1+1"
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
)


@pytest.mark.parametrize("vendor,reporter_class,fixture", SUMMARY_CASES)
def test_vendor_summaries_share_sections_links_and_profile_counts(vendor, reporter_class, fixture):
    reporter = getattr(import_module(f"fwmigrate.vendors.{vendor}.source_report"), reporter_class)()
    source = (Path(__file__).parents[1] / "fixtures" / fixture).read_text(encoding="utf-8")
    analysis = reporter.analyze_source(source)
    inventories = []
    for profile in ("fast", "full"):
        output = BytesIO()
        reporter.export_excel(analysis, output, profile=profile, source_name="review-input.conf")
        workbook = load_workbook(BytesIO(output.getvalue()))
        summary = workbook["Summary"]
        assert workbook.sheetnames[0] == "Summary"
        for detail in workbook.worksheets[1:]:
            header_row = 3 if vendor in {"fortigate", "palo_alto"} else 1
            header = detail.cell(header_row, 1)
            assert header.fill.fgColor.rgb.endswith("0F766E")
            assert header.font.sz == 10
            assert header.alignment.wrap_text
            assert detail.row_dimensions[header_row].height == 30
            assert detail.freeze_panes
        sections = [row[0].value for row in summary if row[0].value in {
            "SOURCE DETAILS", "VALIDATION", "CONFIGURATION INVENTORY", "SOURCE COVERAGE"}]
        assert sections == ["SOURCE DETAILS", "VALIDATION", "CONFIGURATION INVENTORY", "SOURCE COVERAGE"]
        assert not summary.auto_filter.ref
        assert summary["A1"].fill.fgColor.rgb.endswith("17324D")
        assert all(cell.value != "Workbook navigation" for row in summary for cell in row)
        assert any(row[index].value == "Source File" and row[index + 1].value == "review-input.conf"
                   for row in summary for index in (0, 2, 4))
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


def test_fortigate_inventory_escapes_cli_scope_after_reload():
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter

    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source('config firewall address\n edit host\n set subnet 192.0.2.1 255.255.255.255\n next\nend')
    records = tuple(replace(record, cli_scope="\t=1+1") for record in analysis.extracted.source_objects)
    analysis = replace(analysis, extracted=replace(analysis.extracted, source_objects=records))
    output = BytesIO()
    reporter.export_excel(analysis, output, profile="full")
    workbook = load_workbook(BytesIO(output.getvalue()))
    sheet = workbook["FortiGate Source Inventory"]
    column = next(cell.column for cell in sheet[3] if cell.value == "CLI Scope")
    assert sheet.max_row > 3
    assert all(sheet.cell(row, column).value == "'\t=1+1" for row in range(4, sheet.max_row + 1))
    assert all(sheet.cell(row, column).data_type != "f" for row in range(4, sheet.max_row + 1))


@pytest.mark.parametrize("write_only", [False, True])
def test_legacy_summary_finalizer_preserves_title_and_navigation(write_only):
    workbook = Workbook(write_only=write_only)
    if not write_only:
        workbook.remove(workbook.active)
    summary = workbook.create_sheet("Summary")
    detail = workbook.create_sheet("Objects")
    append_report_row(summary, ("Metric", "Value"))
    append_report_row(summary, ("Objects", 1))
    append_report_row(detail, ("Name",))
    append_report_row(detail, ("object",))
    finish_report_workbook(workbook, summary_title="Legacy report")
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(BytesIO(output.getvalue()))
    assert restored["Summary"]["A1"].value == ("Metric" if write_only else "Legacy report")
    assert any(cell.hyperlink and cell.hyperlink.target == "#'Objects'!A1"
               for row in restored["Summary"] for cell in row)
    assert restored["Objects"].auto_filter.ref == "A1:A2"


@pytest.mark.parametrize("summary_values", [(), (("Metric", "Value"), ("Objects", 1))])
def test_legacy_streaming_summary_needs_no_report_counters(summary_values):
    workbook = Workbook(write_only=True)
    summary = workbook.create_sheet("Summary")
    for values in summary_values:
        summary.append(values)
    detail = workbook.create_sheet("Objects")
    append_report_row(detail, ("Name", "Value"))
    append_report_row(detail, ("object", 0))
    finish_report_workbook(workbook)
    output = BytesIO()
    workbook.save(output)
    restored = load_workbook(output)
    assert restored["Summary"].auto_filter.ref is None
    assert restored["Objects"].auto_filter.ref == "A1:B2"
    assert any(cell.hyperlink and cell.hyperlink.target == "#'Objects'!A1"
               for row in restored["Summary"] for cell in row)
