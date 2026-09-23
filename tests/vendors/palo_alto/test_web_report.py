from pathlib import Path

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_web_report_has_expected_sections():
    source = (Path(__file__).parents[2] / "fixtures" / "example_palo_alto.xml").read_text()
    sections = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))["sections"]
    assert {"interfaces", "policies", "nat", "validation"}.issubset(sections)
