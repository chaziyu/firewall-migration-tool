import io
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_excel_report_contains_native_domain_sheets():
    source = (Path(__file__).parents[2] / "fixtures" / "example_palo_alto.xml").read_text()
    output = io.BytesIO()
    reporter = PaloAltoSourceReporter()
    reporter.export_excel(reporter.analyze_source(source), output)
    assert {"Summary", "Interfaces", "Security Policies"}.issubset(load_workbook(io.BytesIO(output.getvalue()), read_only=True).sheetnames)
