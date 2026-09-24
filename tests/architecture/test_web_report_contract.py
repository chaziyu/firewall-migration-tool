import json

from fwmigrate.source_reporting.web_report import (
    REPORT_SECTIONS,
    normalize_web_report,
    validate_web_report_payload,
)


def test_normalize_web_report_adds_empty_sections_without_mutating_input():
    report = {"vendor": "example", "summary": {"interfaces": 1}, "interface_topology": [{"name": "wan"}]}
    normalized = normalize_web_report(report, "example")

    assert report == {"vendor": "example", "summary": {"interfaces": 1}, "interface_topology": [{"name": "wan"}]}
    assert normalized["sections"]["interfaces"] == [{"name": "wan"}]
    assert all(name in normalized["sections"] for name in REPORT_SECTIONS)
    validate_web_report_payload(normalized)
    json.dumps(normalized)


def test_empty_report_sections_are_valid():
    report = normalize_web_report({"summary": {}}, "example")
    validate_web_report_payload(report)
    assert report["sections"]["vpn_phase2"] == []
