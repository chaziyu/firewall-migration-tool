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
        "coverage": {"network_address_overrides": {"status": "AVAILABLE"}},
        "collection": {"status": "PARTIAL", "parts": [
            {"name": "network_address_overrides", "status": "FAILED", "complete": False, "count": 0}]}}
    result = extract_cisco_ftd_source(json.dumps(payload))
    preview = build_ftd_preview(result)
    assert result.config.network_address_overrides == []
    assert result.derived.source_plane_completeness["network_address_overrides"] == "failed"
    assert preview["capability_coverage"]["network_address_overrides"]["status"] == "AVAILABLE"

def test_failed_pbr_collection_remains_failed_when_typed_collection_is_empty():
    payload = {
        "format": "cisco-fmc-rest-export-v1", "collection": {"status": "PARTIAL", "parts": [
            {"name": "device-1/pbr_policies", "status": "FAILED", "complete": False, "count": 0}]},
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {}}],
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    assert result.config.policy_based_routes == []
    assert result.derived.source_plane_completeness["collection:device-1/pbr_policies"] == "failed"
