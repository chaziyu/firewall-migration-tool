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

def test_acp_child_collections_and_explicit_inheritance_are_source_safe():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d1"},
        "collection": {"status": "PARTIAL", "parts": [
            {"name": "access_policies", "status": "SUCCESS", "complete": True, "count": 3},
            {"name": "accesspolicies/child/logging_settings", "status": "SUCCESS", "complete": True, "count": 2},
            {"name": "accesspolicies/child/security_intelligence", "status": "FAILED", "complete": False, "count": 0},
            {"name": "accesspolicies/child/default_actions", "status": "EMPTY", "complete": True, "count": 0},
        ]},
        "access_policies": [
            {"id": "base", "name": "Base", "rules": []},
            {"id": "child", "name": "Child", "metadata": {"inherit": False,
                "parentPolicy": {"id": "base", "name": "Base", "type": "AccessPolicy"}},
             "identityPolicy": {"id": "identity", "name": "Identity", "type": "IdentityPolicy"},
             "logging_settings": [
                 {"id": "log-1", "name": "Beginning", "password": "logging-secret"},
                 {"id": "log-2", "name": "End", "token": "logging-token"}],
             "security_intelligence": [{"id": "si-1", "name": "SI", "apiKey": "si-secret"}],
             "default_actions": [], "rules": []},
            {"id": "missing", "name": "Missing", "rules": []},
        ],
        "objects": {"identitypolicies": [{"id": "identity", "name": "Identity"}]}}
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config
    child = next(policy for policy in config.access_control_policies if policy.source_id == "child")
    missing = next(policy for policy in config.access_control_policies if policy.source_id == "missing")
    assert child.inherit is False and "inherit" in child.explicit_fields
    assert child.base_policy.source_id == "base" and "base_policy" in child.explicit_fields
    assert missing.inherit is None and "inherit" not in missing.explicit_fields
    assert [item.source_id for item in config.access_control_logging_settings] == ["log-1", "log-2"]
    assert config.access_control_logging_settings[0].source_attributes["parent_policy_id"] == "child"
    assert config.security_intelligence_policies[0].source_id == "si-1"
    assert result.derived.source_plane_completeness["acp_logging_settings"] == "present"
    assert result.derived.source_plane_completeness["acp_security_intelligence"] == "failed"
    assert any(item["field"] == "base_policy" and item["target_id"] == "base"
               for item in result.derived.resolved_references)
    assert any(item["field"] == "identity_policy" and item["target_id"] == "identity"
               for item in result.derived.resolved_references)
    for secret in ("logging-secret", "logging-token", "si-secret"):
        assert secret not in json.dumps(config.model_dump())

    preview = CiscoFTDSourceReporter().build_preview(result)
    assert preview["summary"]["access_control_logging_settings"] == 2
    assert preview["summary"]["security_intelligence_policies"] == 1
    output = BytesIO()
    export_ftd_excel(result, output)
    output.seek(0)
    native = list(load_workbook(output, read_only=True)["Native Sources"].values)
    assert any(row[0] == "access_control_logging_settings" and row[2] == "log-1" for row in native)
    assert any(row[0] == "security_intelligence_policies" and row[2] == "si-1" for row in native)
    assert not any(secret in json.dumps(native) for secret in ("logging-secret", "logging-token", "si-secret"))
