from copy import deepcopy
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

def test_identity_admin_sources_are_typed_resolved_and_secret_safe():
    payload = {
        "format": "cisco-fmc-rest-export-v1",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {
            "realms": [{"id": "realm-1", "name": "Corp", "realmType": "AD", "enabled": False,
                "description": "Corporate directory", "baseDn": "dc=example,dc=test", "groupDn": "ou=Groups",
                "groupAttribute": "member", "adPrimaryDomain": "example.test", "updateInterval": 24,
                "directoryConfigurations": [{"hostname": "dc.example.test", "dirPassword": "secret-bind",
                    "ldapPassword": "secret-ldap", "radiusSecret": "secret-radius", "token": "secret-token"}]}],
            "realmusergroups": [{"id": "group-1", "name": "Staff", "realm": {"id": "realm-1", "name": "Corp"}}],
            "realmusers": [
                {"id": "realm-user-1", "name": "alice", "realm": {"id": "realm-1", "name": "Corp"},
                    "metadata": {"resolved": True}, "groups": [{"id": "group-1", "name": "Staff"}]},
                {"id": "realm-user-2", "name": "no-state", "realm": {"id": "realm-1", "name": "Corp"}},
                {"id": "realm-user-2", "name": "alice", "realm": {"id": "realm-1", "name": "Corp"}},
            ],
            "localrealmusers": [{"id": "local-1", "name": "alice", "realm": {"id": "realm-1", "name": "Corp"},
                "enabled": False, "password": "secret-local", "passwordHash": "secret-hash"}],
        },
        "fmc_roles": [{"id": "role-1", "name": "Operators", "description": "Custom operator role",
            "predefined": False, "custom": True, "menuPermissions": [{"menu": "Devices", "permission": "READ"}],
            "systemPermissions": {"manageUsers": False}, "roleEscalation": {"enabled": False}}],
        "fmc_users": [{"id": "fmc-user-1", "username": "alice", "isUserEnabled": False,
            "authenticationMethod": "INTERNAL", "roles": [{"id": "role-1", "name": "Operators", "type": "AuthRole"}]},
            {"id": "fmc-user-2", "username": "orphan", "roles": [{"id": "missing-role", "name": "Missing"}]},
            {"id": "fmc-user-3", "username": "no-state"}],
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config
    realm_user, missing_state, duplicate_user = config.realm_users
    local_user = config.local_realm_users[0]
    fmc_user, _, fmc_missing_state = config.fmc_users

    assert (config.realms[0].realm_type, config.realms[0].enabled, config.realms[0].base_dn) == ("AD", False, "dc=example,dc=test")
    assert config.realms[0].directory_configurations[0]["dirPassword"] == "[REDACTED]"
    assert realm_user.realm.source_id == config.realm_user_groups[0].realm.source_id == local_user.realm.source_id == "realm-1"
    assert realm_user.resolved is True and missing_state.resolved is None
    assert realm_user.groups[0].source_id == "group-1"
    assert local_user.password_configured is True and local_user.enabled is False
    assert fmc_user.username == "alice" and fmc_user.enabled is False
    assert realm_user.name == local_user.name == fmc_user.username == "alice"
    assert (realm_user.source_id, local_user.source_id, fmc_user.source_id) == (
        "realm-user-1", "local-1", "fmc-user-1")
    assert fmc_missing_state.enabled is None and "enabled" not in fmc_missing_state.explicit_fields
    assert config.fmc_user_roles[0].menu_permissions == [{"menu": "Devices", "permission": "READ"}]
    assert config.fmc_user_roles[0].system_permissions == {"manageUsers": False}

    derived = build_ftd_derived_views(config)
    issues = validate_ftd_config(config, derived).issues
    resolved_types = {item["relationship_type"] for item in derived.identity_relationships}
    assert {"realm-user-to-realm", "realm-group-to-realm", "local-realm-user-to-realm",
        "realm-user-to-group", "fmc-user-to-role"} <= resolved_types
    assert any("missing-role" in issue.message for issue in issues)
    assert any(issue.category == "ambiguous-identity-name" for issue in issues)
    assert any(issue.category == "duplicate-identity-id" for issue in issues)

def test_identity_and_vpn_relationships_are_derived_without_source_mutation():
    result = extract_cisco_ftd_source(FIXTURE.read_text(encoding="utf-8"))
    derived = build_ftd_derived_views(result.config)
    assert any(item["relationship_type"] == "fmc-user-to-role" and item["owner_name"] == "operator"
               for item in derived.identity_relationships)
    assert derived.vpn_relationships[0]["endpoints"] == ["HQ"]
