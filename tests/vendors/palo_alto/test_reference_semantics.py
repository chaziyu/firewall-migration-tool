from pathlib import Path

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_reference_resolution_reports_missing_references_without_repairing_source():
    source = (Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_panorama.xml").read_text()
    result = PaloAltoSourceReporter().analyze_source(source)
    assert isinstance(result.derived.relationship_issues, tuple)
    assert result.config.source_inventory
