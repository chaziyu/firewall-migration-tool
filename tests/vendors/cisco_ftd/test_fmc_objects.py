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

def test_canonical_networkaddresses_suppresses_historical_duplicates():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["objects"]["hosts"] = [{"id": "fqdn-1", "name": "updates"}]
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()
    assert [item.source_id for item in config.network_addresses].count("fqdn-1") == 1

def test_typed_source_fields_keep_reference_identity_and_missing_state():
    payload = {
        "source": "fmc-rest-api",
        "objects": {"networkgroups": [
            {"id": "missing-members", "name": "Missing"},
            {"id": "empty-members", "name": "Empty", "objects": []},
            {"id": "members", "name": "Members", "objects": [
                {"id": "host-1", "name": "server", "type": "Host"}
            ]},
        ]},
    }
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()

    assert [group.members for group in config.network_groups[:2]] == [None, []]
    reference = config.network_groups[2].members[0]
    assert (reference.source_id, reference.name, reference.source_type) == ("host-1", "server", "Host")


def test_device_object_override_keeps_base_and_target_identity_separate():
    config = CiscoFMCBundleParser(json.dumps({"source": "fmc-rest-api", "objects": {
        "networkaddresses": [{"id": "base", "name": "Shared", "type": "Host", "value": "10.0.0.1"}],
        "network_address_overrides": [{"id": "override", "name": "Shared", "type": "Host",
            "value": "10.0.0.2", "overrides": {"parent": {"id": "base", "name": "Shared", "type": "Host"},
                "target": {"id": "device-1", "name": "FTD-A", "type": "Device"}}}],
    }})).parse_source()
    assert config.network_addresses[0].value == "10.0.0.1"
    override = config.network_address_overrides[0]
    assert override.value == "10.0.0.2" and override.parent.source_id == "base"
    assert (override.target.source_id, override.target.name) == ("device-1", "FTD-A")
