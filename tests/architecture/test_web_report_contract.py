import json
from copy import deepcopy

import pytest

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


def test_default_copy_isolates_nested_rows_and_preserves_report_fields():
    report = {"summary": {}, "source": {"addresses": [{"name": "a", "members": [], "unknown": None, "enabled": False}]}}
    before = deepcopy(report)
    normalized = normalize_web_report(report, "example")
    normalized["sections"]["addresses"][0]["members"].append("changed")
    assert report == before


def test_owned_report_matches_copy_and_detaches_all_modified_maps():
    shared = {"summary": {"objects": {}, "validation": {"severity_counts": {}}},
              "sections": {"validation": [{"severity": "WARNING"}], "addresses": [{"members": []}]},
              "source": {"unknown": None, "empty": [], "enabled": False}}
    before = deepcopy(shared)
    expected = normalize_web_report(shared, "example")
    owned = dict(shared)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("fwmigrate.source_reporting.web_report.deepcopy", lambda _: pytest.fail("owned reports must not deepcopy rows"))
        assert normalize_web_report(owned, "example", copy=False) is owned
    assert owned == expected
    assert shared == before
    assert owned["sections"]["addresses"][0] is shared["sections"]["addresses"][0]
    validate_web_report_payload(owned)
