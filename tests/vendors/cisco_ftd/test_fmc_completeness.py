import json
from io import BytesIO
from pathlib import Path
from openpyxl import load_workbook

from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import CiscoFMCBundleParser
from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter, extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views
from fwmigrate.vendors.cisco_ftd.validation import validate_ftd_config
from fwmigrate.vendors.cisco_ftd.export.excel import export_ftd_excel
from fwmigrate.vendors.cisco_ftd.web_report import build_ftd_preview


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"

def test_failed_override_collection_is_not_reported_as_known_empty_or_capability_missing():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d1"}, "objects": {},
        "coverage": {"network_address_overrides": {"status": "SUPPORTED"}},
        "collection": {"status": "PARTIAL", "parts": [
            {"name": "network_address_overrides", "status": "FAILED", "complete": False, "count": 0}]}}
    result = extract_cisco_ftd_source(json.dumps(payload))
    preview = build_ftd_preview(result)
    assert result.config.network_address_overrides == []
    assert result.derived.source_plane_completeness["network_address_overrides"] == "failed"
    assert preview["capability_coverage"]["network_address_overrides"]["status"] == "SUPPORTED"

def test_failed_pbr_collection_remains_failed_when_typed_collection_is_empty():
    payload = {
        "format": "cisco-fmc-rest-export-v1", "collection": {"status": "PARTIAL", "parts": [
            {"name": "device-1/pbr_policies", "status": "FAILED", "complete": False, "count": 0}]},
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {}}],
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    assert result.config.policy_based_routes == []
    assert result.derived.source_plane_completeness["collection:device-1/pbr_policies"] == "failed"


def test_collection_completeness_is_exported_separately_from_capability_coverage():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d1"}, "objects": {},
        "coverage": {"network_address_overrides": {"status": "SUPPORTED"}},
        "collection": {"status": "PARTIAL", "parts": [
            {"name": "network_address_overrides", "status": "FAILED", "complete": False, "count": 0}]}}
    result = extract_cisco_ftd_source(json.dumps(payload))
    preview = build_ftd_preview(result)
    assert preview["capability_coverage"]["network_address_overrides"]["status"] == "SUPPORTED"
    assert preview["collection_completeness"] == {
        "provided": True,
        "status": "PARTIAL",
        "parts": [{
            "name": "network_address_overrides",
            "status": "FAILED",
            "complete": False,
            "count": 0,
        }],
    }
    assert preview["source_plane_completeness"]["network_address_overrides"] == "failed"

    output = BytesIO()
    export_ftd_excel(result, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)
    headers = [cell.value for cell in workbook["Collection Completeness"][1]]
    row = dict(zip(headers, next(workbook["Collection Completeness"].iter_rows(min_row=2, values_only=True))))
    assert row == {
        "Collection Part": "network_address_overrides",
        "Status": "FAILED",
        "Complete": False,
        "Count": 0,
    }
    semantic_headers = [cell.value for cell in workbook["Semantic Completeness"][1]]
    semantic_rows = [dict(zip(semantic_headers, row)) for row in
                     workbook["Semantic Completeness"].iter_rows(min_row=2, values_only=True)]
    assert {"Source Family": "network_address_overrides", "Derived Status": "failed"} in semantic_rows


def test_missing_collection_metadata_is_reported_as_unknown_not_zero():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "objects": {"networkaddresses": [{"id": "h1", "name": "Host", "type": "Host", "value": "192.0.2.1"}]},
    }))
    preview = build_ftd_preview(result)
    assert preview["collection_completeness"] == {
        "provided": False,
        "status": "NOT_PROVIDED",
        "parts": [],
    }

    output = BytesIO()
    export_ftd_excel(result, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)
    summary = dict(workbook["Summary"].iter_rows(min_row=2, values_only=True))
    assert summary["Collection Status"] == "NOT_PROVIDED"
    assert summary["Collection Parts"] == "Not provided"
    assert summary["Incomplete Collection Parts"] == "Not provided"
    completeness = list(workbook["Collection Completeness"].iter_rows(min_row=2, values_only=True))
    assert completeness == [("Collection metadata", "NOT_PROVIDED", None, None)]
