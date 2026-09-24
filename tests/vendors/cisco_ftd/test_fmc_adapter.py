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


def test_selected_fmc_domains_preserve_native_ownership_and_order():
    config = CiscoFMCBundleParser(FIXTURE.read_text(encoding="utf-8")).parse_source()
    assert [x.name for x in config.time_ranges] == ["business-hours"]
    assert config.network_addresses[0].raw_extra["type"] == "FQDN"
    assert config.access_control_policies[0].rules[0].source_zones[0].name == "inside"
    assert config.access_control_policies[0].rules[0].destination_zones[0].name == "outside"
    assert len(config.intrusion_rule_groups) == 1
    assert not config.intrusion_rule_behaviors
    assert not config.intrusion_rule_overrides
    assert not [item for item in config.native_resources
                if item.source_attributes.get("parent_policy_type") == "intrusionpolicies"]
    assert config.s2s_vpn_endpoints[0].source_attributes["parent_topology_id"] == "vpn-1"
    assert config.ra_vpn_connection_profiles[0].source_attributes["parent_policy_id"] == "ra-1"
    assert config.routes[0].source_attributes["device_name"] == "FTD-A"
    assert config.dhcp_servers[0].source_attributes["device_id"] == "device-1"
    assert config.file_policies[0].rules[0].position == 1
    assert config.file_policies[0].rules[0].collection_order == 1
    assert "rules" not in config.file_policies[0].raw_extra


def test_inspection_policy_rules_are_typed_ordered_resolved_and_complete():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d1"},
        "objects": {
            "networkaddresses": [{"id": "net1", "name": "Inside"}],
            "protocolportobjects": [{"id": "svc1", "name": "HTTPS", "protocol": "TCP", "port": "443"}],
            "securityzones": [{"id": "zone1", "name": "Inside Zone"}],
            "vlanobjects": [{"id": "vlan1", "name": "VLAN 20"}],
            "internalcertificates": [{"id": "cert1", "name": "CA"}],
            "siurllists": [{"id": "si1", "name": "Threat URLs", "url": "https://feed.test/list"}],
            "siurlfeeds": [{"id": "feed1", "name": "Live Feed", "url": "https://live.test/feed",
                "entries": ["runtime.example"]}],
            "filepolicies": [{"id": "f1", "name": "Files", "description": "Files", "rules": [
                {"id": "fr2", "name": "second", "metadata": {"ruleIndex": 2}, "action": "BLOCK",
                 "protocol": "HTTP", "direction": "DOWNLOAD",
                 "fileTypes": [{"id": "pdf", "name": "PDF"}], "analysis": ["spero"], "storeFiles": ["MALWARE"]},
                {"id": "fr1", "name": "first", "order": 1, "action": "MONITOR"}]} ,
                {"id": "f2", "name": "Empty", "rules": []}, {"id": "f3", "name": "Unknown"}],
            "decryptionpolicies": [{"id": "dec1", "name": "Decrypt", "defaultAction": "Do Not Decrypt",
                "undecryptableActions": {"decryptionErrors": "BLOCK"}, "advancedOptions": {"strict": True}, "rules": [{
                    "id": "dr1", "name": "Decrypt web", "metadata": {"ruleIndex": 4}, "ruleAction": "DECRYPT_RESIGN",
                    "sourceNetworks": {"objects": [{"id": "net1", "name": "Inside"}]},
                    "sourcePorts": {"objects": [{"id": "svc1", "name": "HTTPS"}]},
                    "decryptionCerts": {"objects": [{"id": "cert1", "name": "CA"}]},
                    "tlsVersions": {"tls13": True}, "certStatuses": {"revoked": False}, "privateKey": "must-not-leak"}]}],
            "dnspolicies": [{"id": "dns1", "name": "DNS", "umbrellaSettings": {"enabled": True},
                "block_rules": [{"id": "dnsr1", "name": "Block feed", "metadata": {"ruleIndex": 3}, "ruleAction": "BLOCK",
                    "sourceZones": [{"id": "zone1", "name": "Inside Zone"}],
                    "sourceNetworks": [{"id": "net1", "name": "Inside"}],
                    "vlanTags": [{"id": "vlan1", "name": "VLAN 20"}],
                    "dnsLists": {"objects": [{"id": "si1", "name": "Threat URLs"}]},
                    "dnsFeeds": {"objects": [{"id": "feed1", "name": "Live Feed"}]}}]}],
        },
        "collection": {"status": "PARTIAL", "parts": [
            {"name": "filepolicies/f3/rules", "status": "FAILED", "complete": False}]},
        "access_policies": [{"id": "acp1", "name": "ACP", "decryptionPolicy": {"id": "dec1", "name": "Decrypt"},
            "dnsPolicy": {"id": "dns1", "name": "DNS"}, "rules": [{"id": "acpr1", "name": "Rule",
                "filePolicy": {"id": "f1", "name": "Files"}}]}]}
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config
    assert [(rule.position, rule.collection_order, rule.action) for rule in config.file_policies[0].rules] == [
        (2, 1, "BLOCK"), (1, 2, "MONITOR")]
    assert "ruleIndex" not in config.file_policies[0].rules[0].raw_extra.get("metadata", {})
    assert config.file_policies[1].rules == [] and config.file_policies[2].rules is None
    assert config.file_policies[0].rules[0].malware_inspection == ["spero"]
    decrypt = config.decryption_policies[0]
    assert decrypt.default_action == "Do Not Decrypt" and decrypt.undecryptable_action == {"decryptionErrors": "BLOCK"}
    assert decrypt.rules[0].action == "DECRYPT_RESIGN"
    dns = config.dns_policies[0]
    assert dns.rules[0].action == "BLOCK" and dns.rules[0].position == 3 and dns.rules[0].collection_order == 1
    assert "must-not-leak" not in json.dumps(config.model_dump())
    assert "runtime.example" not in json.dumps(config.model_dump())
    kinds = {item["kind"] for item in result.derived.resolved_references}
    assert {"NETWORK_ADDRESS", "SERVICE_OBJECT", "CERTIFICATE", "SECURITY_ZONE", "VLAN_OBJECT",
            "SECURITY_INTELLIGENCE_SOURCE", "DECRYPTION_POLICY", "DNS_POLICY", "FILE_POLICY"} <= kinds
    assert result.derived.source_plane_completeness["file_rules"] == "failed"
    assert not {"filepolicyrules", "decryptionpolicyrules", "block_rules"} & {
        item.source_attributes.get("resource_type") for item in config.native_resources}
    paths = {item.source_path for item in result.inventory_items}
    assert {"fmc-rest-bundle/file-policy-rules", "fmc-rest-bundle/decryption-policy-rules",
            "fmc-rest-bundle/dns-policy-rules"} <= paths
    assert result.derived.inspection_relationships
    preview = CiscoFTDSourceReporter().build_preview(result)
    assert preview["summary"]["dns_rules"] == 1
    assert "must-not-leak" not in json.dumps(preview)
    workbook_bytes = BytesIO()
    export_ftd_excel(result, workbook_bytes)
    workbook_bytes.seek(0)
    exported = load_workbook(workbook_bytes, read_only=True)
    assert all("must-not-leak" not in str(cell.value)
               for sheet in exported.worksheets for row in sheet.iter_rows() for cell in row)
    inspection_rows = list(exported["Inspection Policies"].values)
    assert ("File", "Empty", "f2", None, None, "KNOWN EMPTY") == inspection_rows[3][:6]
    assert ("File", "Unknown", "f3", None, None, "UNKNOWN") == inspection_rows[4][:6]
    assert any(row[0] == "Decryption" and row[9] == "DECRYPT_RESIGN" for row in inspection_rows[1:])


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
    assert fmc_missing_state.enabled is None and "enabled" not in fmc_missing_state.explicit_fields
    assert config.fmc_user_roles[0].menu_permissions == [{"menu": "Devices", "permission": "READ"}]
    assert config.fmc_user_roles[0].system_permissions == {"manageUsers": False}

    before = config.model_dump()
    derived = build_ftd_derived_views(config)
    issues = validate_ftd_config(config, derived).issues
    resolved_types = {item["relationship_type"] for item in derived.identity_relationships}
    assert {"realm-user-to-realm", "realm-group-to-realm", "local-realm-user-to-realm",
        "realm-user-to-group", "fmc-user-to-role"} <= resolved_types
    assert any("missing-role" in issue.message for issue in issues)
    assert any(issue.category == "ambiguous-identity-name" for issue in issues)
    assert any(issue.category == "duplicate-identity-id" for issue in issues)
    assert config.model_dump() == before

    preview_model = CiscoFTDSourceReporter().build_preview(result)
    assert preview_model["summary"]["realm_user_groups"] == 1
    assert preview_model["summary"]["local_realm_users"] == 1
    assert preview_model["summary"]["fmc_user_roles"] == 1
    preview = json.dumps(preview_model, default=str)
    workbook = BytesIO()
    export_ftd_excel(result, workbook)
    workbook.seek(0)
    workbook_data = load_workbook(workbook, read_only=True)
    native_rows = list(workbook_data["Native Sources"].values)
    role_row = next(row for row in native_rows if row[0] == "fmc_user_roles" and row[2] == "role-1")
    assert '"menuPermissions"' in role_row[5] and '"systemPermissions"' in role_row[5]
    exported = json.dumps([[cell.value for cell in row] for sheet in workbook_data for row in sheet.iter_rows()], default=str)
    evidence = json.dumps((result.inventory_items, issues), default=str)
    for output in (json.dumps(config.model_dump()), preview, exported, evidence):
        for secret in ("secret-bind", "secret-ldap", "secret-radius", "secret-token", "secret-local", "secret-hash"):
            assert secret not in output


def test_fmc_dhcp_interface_reference_is_typed_scoped_and_keeps_missing_state():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["devices"][0]["resources"]["dhcp_servers"][0]["vendorField"] = "preserved"
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()
    server = config.dhcp_servers[0]

    assert server.interface.name == "inside"
    assert server.explicit_fields == ["interface"]
    assert server.raw_extra["interfaceName"] == "inside"
    assert server.raw_extra["vendorField"] == "preserved"
    assert server.source_attributes["device_id"] == "device-1"
    before = server.model_dump()
    derived = build_ftd_derived_views(config)
    assert any(issue.owner == server.name and issue.field == "interface"
               for issue in derived.unresolved_references)
    assert any(issue.source_object == server.name and issue.category == "unresolved-reference"
               and "in interface" in issue.message for issue in validate_ftd_config(config, derived).issues)
    assert server.model_dump() == before

    del payload["devices"][0]["resources"]["dhcp_servers"][0]["interfaceName"]
    missing = CiscoFMCBundleParser(json.dumps(payload)).parse_source().dhcp_servers[0]
    assert missing.interface is None
    assert "interface" not in missing.explicit_fields


def test_fmc_override_acp_assignment_ips_and_dhcp_source_state_remain_separate():
    payload = {
        "format": "cisco-fmc-rest-export-v1", "domain": {"id": "d1", "name": "Global"},
        "access_policies": [
            {"id": "base-acp", "name": "Base", "rules": []},
            {"id": "child-acp", "name": "Child", "description": "Child policy", "metadata": {
                "inherit": False, "parentPolicy": {"id": "base-acp", "name": "Base", "type": "AccessPolicy"}},
             "defaultAction": {"id": "default-1", "name": "Default", "type": "AccessPolicyDefaultAction"},
             "identityPolicy": {"id": "identity-1", "name": "Identity", "type": "IdentityPolicy"},
             "logging_settings": {"logAtBeginning": True},
             "default_actions": [{"id": "default-1", "name": "Default", "action": "BLOCK"}], "rules": []},
        ],
        "objects": {"networkaddresses": [{"id": "net-1", "name": "Shared", "type": "Host", "value": "10.0.0.1"}],
            "identitypolicies": [{"id": "identity-1", "name": "Identity"}],
            "network_address_overrides": [
                {"id": "ov-1", "name": "Shared", "type": "Host", "value": "10.0.0.2",
                 "overridable": True, "overrides": {"parent": {"id": "net-1", "name": "Shared", "type": "Host"},
                    "target": {"id": "dev-1", "name": "FTD-A", "type": "Device"}}, "password": "must-not-leak"},
                {"id": "ov-2", "name": "Shared", "type": "Host", "value": "10.0.0.3",
                 "overrides": {"parent": {"id": "net-1", "name": "Shared", "type": "Host"},
                    "target": {"id": "dev-2", "name": "FTD-B", "type": "Device"}}}],
            "intrusionpolicies": [{"id": "ips-1", "name": "IPS", "rules": [
                {"id": "beh-1", "ruleId": "sig-1", "state": "enabled", "action": "alert"}],
                "overrides": [{"id": "ov-rule-1", "ruleId": "sig-1", "state": "disabled"}]}],
            "policy_assignments": [{"id": "assignment-1", "name": "ACP assignment", "policy":
                {"id": "child-acp", "name": "Child", "type": "AccessPolicy"}, "targets": [
                {"id": "dev-1", "name": "FTD-A", "type": "Device"}, {"id": "dev-2", "name": "FTD-B", "type": "Device"}]}]},
        "devices": [{"id": "dev-1", "name": "FTD-A", "resources": {
            "dhcp_servers": [{"id": "dhcp-1", "name": "DHCP", "interfaceName": "inside", "addressPool": "10.0.0.10-10.0.0.20"}],
            "dhcp_relay_settings": [{"id": "relay-1", "name": "Relay", "dhcpRelayAgent": [], "dhcpRelayServers": [],
                "ipv4TimeoutInSec": "20", "trustAllInformation": True}],
            "ftd_interfaces": [{"id": "if-1", "name": "GigabitEthernet0/0.10", "interfaceType": "SubInterface"}],
            "static_routes": [{"id": "route-1", "name": "inside-route", "network": {"id": "net-1", "name": "Shared", "type": "Host"}, "addressFamily": "IPv4"}],
        }}],
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config

    assert config.network_addresses[0].value == "10.0.0.1"
    assert [item.value for item in config.network_address_overrides] == ["10.0.0.2", "10.0.0.3"]
    assert config.network_address_overrides[0].parent.source_id == "net-1"
    assert config.network_address_overrides[0].target.name == "FTD-A"
    assert config.access_control_policies[1].inherit is False
    assert {"inherit", "base_policy"} <= set(config.access_control_policies[1].explicit_fields)
    assert config.access_control_policies[1].logging_settings == {"logAtBeginning": True}
    assert config.access_control_policies[1].base_policy.source_id == "base-acp"
    assert len(config.access_control_default_actions) == 1
    assert len(config.policy_assignments[0].targets) == 2
    assert any(item["field"] == "identity_policy" and item["target_id"] == "identity-1"
               for item in result.derived.resolved_references)
    assert [(item.rule_id, item.state) for item in config.intrusion_rule_overrides] == [("sig-1", "disabled")]
    assert config.dhcp_relay_settings[0].ipv4_timeout_seconds == "20"
    assert "dhcpRelayAgent" not in config.dhcp_servers[0].raw_extra
    assert not any(item.source_attributes.get("resource_type") == "dhcp_relay_settings" for item in config.native_resources)

    before = config.model_dump()
    assert any(item["field"] == "parent" and item["target_id"] == "net-1"
               for item in result.derived.resolved_references)
    assert any(item.source_name == "inside-route" and item.normalized_destination == "10.0.0.1/32"
               for item in result.derived.normalized_routes), result.derived.normalized_routes
    assert any(item.category == "dhcp-server-relay-conflict" for item in result.validation.issues)
    assert any(item.device_id == "dev-1" and item.name == "GigabitEthernet0/0.10"
               for item in result.derived.interface_topology.interfaces)
    assert config.model_dump() == before

    preview = result
    output = BytesIO()
    export_ftd_excel(preview, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)
    assert workbook["Object Overrides"].max_row == 3
    assert workbook["ACP Policies"].max_row == 3
    assert workbook["DHCP"].max_row == 3
    assert "must-not-leak" not in json.dumps(config.model_dump())


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

    assert not hasattr(config, "managed_objects")
    assert [group.members for group in config.network_groups[:2]] == [None, []]
    reference = config.network_groups[2].members[0]
    assert (reference.source_id, reference.name, reference.source_type) == ("host-1", "server", "Host")


def test_intrusion_behavior_group_membership_conflicts_and_acp_references():
    payload = {
        "format": "cisco-fmc-rest-export-v1", "domain": {"id": "domain-1", "name": "Global"},
        "objects": {
            "variablesets": [{"id": "vars-1", "name": "Variables"}],
            "intrusionpolicies": [{"id": "ips-1", "name": "IPS", "variableSet": {"id": "vars-1", "name": "Variables"},
                "rules": [{"id": "behavior-1", "ruleId": "sig-1", "state": "enabled", "action": "alert"}],
                "rule_groups": [{"id": "group-1", "name": "Group", "rules": [
                    {"id": "behavior-1", "ruleId": "sig-1", "state": "disabled", "action": "drop"},
                    {"id": "behavior-2", "ruleId": "sig-2"}]}]}],
        },
        "access_policies": [{"id": "acp-1", "name": "ACP", "rules": [{"id": "acp-rule-1", "name": "Allow",
            "ipsPolicy": {"id": "ips-1", "name": "IPS"}, "variableSet": {"id": "vars-1", "name": "Variables"}}]}],
        "collection": {"status": "SUCCESS", "parts": [
            {"name": "intrusionpolicies", "status": "SUCCESS", "complete": True},
            {"name": "intrusionpolicies/ips-1/rule_groups", "status": "SUCCESS", "complete": True},
            {"name": "intrusionpolicies/ips-1/rules", "status": "SUCCESS", "complete": True}]},
    }
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()
    assert len(config.intrusion_policies) == len(config.intrusion_rule_groups) == 1
    assert [(item.source_id, item.rule_id, item.state, item.action) for item in config.intrusion_rule_behaviors] == [
        ("behavior-1", "sig-1", "enabled", "alert")]
    assert not config.intrusion_rule_overrides
    behavior = config.intrusion_rule_behaviors[0]
    assert behavior.source_attributes["group_membership_evidence"][0]["rule_group_id"] == "group-1"
    assert behavior.source_attributes["conflicting_group_payload"][0]["conflicting_fields"]["action"] == {
        "behavior": "alert", "group": "drop"}
    assert not [item for item in config.native_resources
                if item.source_attributes.get("parent_policy_type") == "intrusionpolicies"]

    derived = build_ftd_derived_views(config)
    assert {("intrusion_rule_groups", "present"), ("intrusion_rule_behaviors", "present")} <= set(
        derived.source_plane_completeness.items())
    assert any(item["rule_group_id"] == "group-1" and item["rule_behavior_id"] == "behavior-1"
               for item in derived.intrusion_relationships)
    resolved = {(item["owner"], item["field"], item["kind"]) for item in derived.resolved_references}
    assert ("IPS", "variable_set", "VARIABLE_SET") in resolved
    assert ("Allow", "intrusion_policy", "INTRUSION_POLICY") in resolved
    assert ("Allow", "variable_set", "VARIABLE_SET") in resolved
    assert any(item.category == "intrusion-rule-group-conflict" for item in validate_ftd_config(config, derived).issues)
    before = config.model_dump()
    build_ftd_derived_views(config)
    validate_ftd_config(config, derived)
    assert config.model_dump() == before

    analysis = extract_cisco_ftd_source(json.dumps(payload))
    preview = CiscoFTDSourceReporter().build_preview(analysis)["summary"]
    assert preview["intrusion_policies"] == 1
    assert preview["intrusion_rule_groups"] == 1
    assert preview["intrusion_rule_behaviors"] == 1
    assert preview["intrusion_rule_overrides"] == 0
    assert {item.source_type for item in analysis.inventory_items} >= {
        "intrusion_rule_group", "intrusion_rule_behavior"}
    workbook_bytes = BytesIO()
    export_ftd_excel(analysis, workbook_bytes)
    workbook_bytes.seek(0)
    native_rows = list(load_workbook(workbook_bytes, read_only=True)["Native Sources"].values)
    assert {tuple(row[:2]) for row in native_rows[1:]} >= {
        ("intrusion_rule_groups", "Group"), ("intrusion_rule_behaviors", "behavior-1")}


def test_intrusion_group_only_and_missing_vs_empty_child_collections():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "d", "name": "Global"},
        "objects": {"intrusionpolicies": [{"id": "p", "name": "IPS", "rule_groups": [
            {"id": "g", "name": "Group", "rules": [{"id": "sig", "name": "Signature"}]}]}]},
        "collection": {"status": "PARTIAL", "parts": [
            {"name": "intrusionpolicies", "status": "SUCCESS", "complete": True},
            {"name": "intrusionpolicies/p/rule_groups", "status": "SUCCESS", "complete": True},
            {"name": "intrusionpolicies/p/rules", "status": "FAILED", "complete": False}]}}
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()
    assert len(config.intrusion_rule_groups) == 1
    assert not config.intrusion_rule_behaviors and not config.intrusion_rule_overrides
    derived = build_ftd_derived_views(config)
    assert derived.source_plane_completeness["intrusion_rule_groups"] == "present"
    assert derived.source_plane_completeness["intrusion_rule_behaviors"] == "failed"
    assert any(item["rule_group_id"] == "g" and item["rule_id"] == "sig" and
               item["rule_behavior_id"] is None for item in derived.intrusion_relationships)

    payload["objects"]["intrusionpolicies"][0]["rules"] = []
    payload["collection"]["parts"] = [*payload["collection"]["parts"][:2],
        {"name": "intrusionpolicies/p/rules", "status": "EMPTY", "complete": True}]
    derived = build_ftd_derived_views(CiscoFMCBundleParser(json.dumps(payload)).parse_source())
    assert derived.source_plane_completeness["intrusion_rule_behaviors"] == "known-empty"
    payload["collection"]["parts"] = [payload["collection"]["parts"][0]]
    derived = build_ftd_derived_views(CiscoFMCBundleParser(json.dumps(payload)).parse_source())
    assert derived.source_plane_completeness["intrusion_rule_groups"] == "unknown"
    assert derived.source_plane_completeness["intrusion_rule_behaviors"] == "unknown"


def test_fmc_ike_ipsec_objects_are_typed_with_version_and_without_native_duplicates():
    payload = {
        "format": "cisco-fmc-rest-export-v1",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {
            "ikev1policies": [{"id": "ike1", "name": "Legacy-IKE", "safeExtra": "kept"}],
            "ikev2policies": [{"id": "ike2", "name": "Modern-IKE"}],
            "ikev1ipsecproposals": [{"id": "prop1", "name": "Legacy-Proposal"}],
            "ikev2ipsecproposals": [{"id": "prop2", "name": "Modern-Proposal"}],
        },
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config

    assert [(item.source_id, item.ike_version) for item in config.ike_policies] == [
        ("ike1", "IKEv1"), ("ike2", "IKEv2")]
    assert [(item.source_id, item.ike_version) for item in config.ipsec_proposals] == [
        ("prop1", "IKEv1"), ("prop2", "IKEv2")]
    assert config.ike_policies[0].domain_id == "domain-1"
    assert config.ike_policies[0].raw_extra["safeExtra"] == "kept"
    assert config.ike_policies[0].source_plane == "fmc-rest-bundle"
    assert config.ike_policies[0].source_attributes["resource_type"] == "ikev1policies"
    assert config.ike_policies[0].explicit_fields == []
    assert not {item.source_attributes["resource_type"] for item in config.native_resources} & {
        "ikev1policies", "ikev2policies", "ikev1ipsecproposals", "ikev2ipsecproposals"}

    assert {item.source_path for item in result.inventory_items if item.source_id in {"ike1", "prop1"}} == {
        "fmc-rest-bundle/ike-policies", "fmc-rest-bundle/ipsec-proposals"}


def test_legacy_ike_ipsec_bundle_uses_top_level_collections_without_guessing_version():
    payload = {
        "ike_policies": [{"id": "legacy-ike", "name": "Legacy", "ike_version": "IKEv2"}],
        "ipsec_proposals": [{"id": "legacy-proposal", "name": "Legacy Proposal"}],
    }
    config = CiscoFMCBundleParser(json.dumps(payload)).parse_source()

    assert len(config.ike_policies) == len(config.ipsec_proposals) == 1
    assert config.ike_policies[0].ike_version == "IKEv2"
    assert config.ike_policies[0].explicit_fields == ["ike_version"]
    assert config.ipsec_proposals[0].ike_version is None
    assert config.ike_policies[0].source_attributes["resource_type"] == "ike_policies"


def test_expanded_fmc_source_families_are_typed_scoped_and_secret_safe():
    payload = {
        "format": "cisco-fmc-rest-export-v1", "domain": {"id": "domain-1", "name": "Global"},
        "objects": {
            "slamonitors": [{"id": "sla-1", "name": "probe"}],
            "ipv4addresspools": [{"id": "pool4", "name": "v4-pool", "startAddress": "192.0.2.10", "endAddress": "192.0.2.20"}],
            "ipv6addresspools": [{"id": "pool6", "name": "v6-pool", "value": "2001:db8::/64"}],
            "internalcertificates": [{"id": "cert-1", "name": "vpn-cert", "issuer": "CA", "subject": "fw",
                "privateKey": "private-secret", "pkcs12Password": "p12-secret"}],
            "device_certificates": [{"id": "cert-2", "name": "device-cert", "deviceId": "device-1"}],
            "certificatemaps": [{"id": "map-1", "name": "cert-map"}],
            "certenrollments": [{"id": "enroll-1", "name": "enrollment"}],
            "grouppolicies": [{"id": "group-1", "name": "vpn-group", "addressPools": [{"id": "pool4", "name": "v4-pool"}]}],
            "s2svpns": [{"id": "s2s-1", "name": "site-link", "endpoints": [{"id": "endpoint-1", "name": "peer",
                "protectedNetworks": [{"id": "net-1", "name": "remote-net"}], "vti": {"id": "vti-1", "name": "Tunnel1"}}],
                "ike_settings": [{"id": "ike-settings-1", "name": "ike-settings", "ikePolicy": {"id": "ike-1", "name": "IKE"},
                    "certificates": [{"id": "cert-1", "name": "vpn-cert"}, {"id": "missing-cert", "name": "missing-cert"}],
                    "preSharedKey": "psk-secret"}],
                "ipsec_settings": [{"id": "ipsec-settings-1", "name": "ipsec-settings", "ipsecProposal": {"id": "proposal-1", "name": "Proposal"}}],
                "advanced_settings": [{"id": "s2s-advanced-1", "name": "advanced"}]}],
            "ikev2policies": [{"id": "ike-1", "name": "IKE"}],
            "ikev2ipsecproposals": [{"id": "proposal-1", "name": "Proposal"}],
            "ravpns": [{"id": "ra-1", "name": "remote-access", "groupPolicies": [{"id": "group-1", "name": "vpn-group"}],
                "addressPools": [{"id": "pool4", "name": "v4-pool"}], "connection_profiles": [{"id": "profile-1", "name": "profile",
                    "defaultGroupPolicy": {"id": "group-1", "name": "vpn-group"}, "addressPools": [{"id": "pool4", "name": "v4-pool"}],
                    "certificateMaps": [{"id": "map-1", "name": "cert-map"}]}],
                "ipsec_advanced_settings": [{"id": "ra-ipsec-1", "name": "ipsec"}],
                "ldap_attribute_maps": [{"id": "ldap-1", "name": "ldap"}],
                "load_balance_settings": [{"id": "lb-1", "name": "load-balance"}],
                "address_assignment_settings": [{"id": "assign-1", "name": "assignment", "addressPools": [{"id": "pool4", "name": "v4-pool"}]}],
                "secure_client_customization_settings": [{"id": "secure-1", "name": "secure-client"}],
                "ipsec_crypto_maps": [{"id": "crypto-1", "name": "crypto-map"}]}],
            "prefilterpolicies": [{"id": "prefilter-1", "name": "prefilter", "rules": [{"id": "pref-rule-1", "name": "rule", "position": 1, "action": "FASTPATH", "conditions": {"source": "any"}}],
                "default_actions": [{"id": "pref-default-1", "name": "default"}]}],
            "networkanalysispolicies": [{"id": "nap-1", "name": "nap", "inspectorconfigs": [{"id": "inspect-1", "name": "inspect"}],
                "inspectoroverrideconfigs": [{"id": "override-1", "name": "override"}]}],
            "futurething": [{"id": "unknown-1", "name": "unknown"}],
        },
        "access_policies": [{"id": "acp-1", "name": "acp", "prefilterPolicy": {"id": "prefilter-1", "name": "prefilter"},
            "networkAnalysisPolicy": {"id": "nap-1", "name": "nap"}}],
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {
            "static_routes": [{"id": "global-route", "name": "global-route", "virtualRouter": {"id": "vr-global", "name": "Global"},
                "slaMonitor": {"id": "sla-1", "name": "probe"}}],
            "pbr_policies": [{"id": "global-pbr", "name": "global-pbr"}], "ecmp_zones": [{"id": "global-ecmp", "name": "global-ecmp"}],
            "virtual_routers": [{"id": "vr-a", "name": "VR-A", "interfaces": [{"id": "if-1", "name": "outside"}], "resources": {
                "ipv4_static_routes": [{"id": "vr-route", "name": "vr-route"}],
                "pbr_policies": [{"id": "vr-pbr", "name": "vr-pbr"}], "ecmp_zones": [{"id": "vr-ecmp", "name": "vr-ecmp"}]}}],
        }}],
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config

    assert [item.source_id for item in config.virtual_routers] == ["vr-a"]
    assert {item.source_id for item in config.policy_based_routes} == {"global-pbr", "vr-pbr"}
    vr_pbr = next(item for item in config.policy_based_routes if item.source_id == "vr-pbr")
    assert (vr_pbr.device_id, vr_pbr.source_attributes["virtual_router_id"], vr_pbr.source_attributes["virtual_router_name"]) == ("device-1", "vr-a", "VR-A")
    assert {item.source_id for item in config.ecmp_zones} == {"global-ecmp", "vr-ecmp"}
    assert len(config.routes) == 2
    assert [(item.source_id, item.address_family) for item in config.address_pools] == [("pool4", "IPv4"), ("pool6", "IPv6")]
    assert {item.source_id for item in config.certificates} == {"cert-1", "cert-2"}
    assert next(item for item in config.certificates if item.source_id == "cert-2").device_id == "device-1"
    assert config.certificates[0].private_key_present is True
    assert "private-secret" not in json.dumps(config.model_dump())
    assert "p12-secret" not in json.dumps(config.model_dump())
    assert "psk-secret" not in json.dumps(config.model_dump())
    assert config.s2s_ike_settings[0].source_attributes["parent_topology_id"] == "s2s-1"
    assert config.s2s_ike_settings[0].psk_present is True
    assert config.ra_vpn_connection_profiles[0].parent_policy_id == "ra-1"
    assert config.prefilter_rules[0].position == 1 and config.prefilter_rules[0].action == "FASTPATH"
    assert config.inspector_configs[0].source_attributes["parent_policy_id"] == "nap-1"
    before = config.model_dump()
    derived = build_ftd_derived_views(config)
    validation = validate_ftd_config(config, derived)
    resolved_kinds = {item["kind"] for item in derived.resolved_references}
    assert {"CERTIFICATE", "CERTIFICATE_MAP", "ADDRESS_POOL", "GROUP_POLICY", "PREFILTER_POLICY",
        "NETWORK_ANALYSIS_POLICY", "VIRTUAL_ROUTER", "SLA_MONITOR", "IPSEC_PROPOSAL"} <= resolved_kinds
    assert any(item.reference_id == "missing-cert" for item in derived.unresolved_references)
    assert any(item.category == "unresolved-reference" for item in validation.issues)
    assert config.model_dump() == before
    inventory_paths = {item.source_path for item in result.inventory_items}
    assert {"fmc-rest-bundle/virtual-routers", "fmc-rest-bundle/policy-based-routes",
        "fmc-rest-bundle/certificates", "fmc-rest-bundle/address-pools",
        "fmc-rest-bundle/prefilter-policies", "fmc-rest-bundle/network-analysis-policies"} <= inventory_paths
    workbook_bytes = BytesIO()
    export_ftd_excel(result, workbook_bytes)
    workbook_bytes.seek(0)
    native_rows = list(load_workbook(workbook_bytes, read_only=True)["Native Sources"].values)
    assert ("virtual_routers", "VR-A") in {(row[0], row[1]) for row in native_rows[1:]}
    assert ("prefilter_rules", "rule") in {(row[0], row[1]) for row in native_rows[1:]}
    typed_families = {"virtual_router", "pbr_policies", "ecmp_zones", "slamonitors", "ipv4addresspools",
        "ipv6addresspools", "internalcertificates", "device_certificates", "certificatemaps", "certenrollments",
        "grouppolicies", "ike_settings", "ipsec_settings", "advanced_settings", "ipsec_advanced_settings",
        "ldap_attribute_maps", "load_balance_settings", "address_assignment_settings",
        "secure_client_customization_settings", "ipsec_crypto_maps", "rules", "default_actions",
        "inspectorconfigs", "inspectoroverrideconfigs"}
    assert not any(item.source_attributes.get("resource_type") in typed_families for item in config.native_resources)
    assert any(item.source_id == "unknown-1" and item.source_attributes["resource_type"] == "futurething"
        for item in config.native_resources)
    assert any(item.source_id == "prefilter-1" for item in result.inventory_items)
    assert CiscoFTDSourceReporter().build_preview(result)["summary"]["virtual_routers"] == 1


def test_s2s_crypto_fields_keep_fmc_ownership_and_redact_manual_psk():
    payload = {"format": "cisco-fmc-rest-export-v1", "domain": {"id": "domain-1"}, "objects": {
        "networkaddresses": [{"id": "net-1", "name": "LAN", "value": "10.0.0.0/24"}],
        "internalcertificates": [{"id": "cert-1", "name": "VPN Certificate"}],
        "s2svpns": [{"id": "vpn-1", "name": "Branch", "endpoints": [{
            "id": "endpoint-1", "name": "peer", "peerType": "PEER", "connectionType": "BIDIRECTIONAL",
            "localIdentityType": "HOSTNAME", "localIdentityString": "branch.example",
            "isLocalTunnelIdEnabled": True, "protectedNetworks": {"networks": [{"id": "net-1", "name": "LAN"}]},
        }], "ike_settings": [{"id": "ike-settings", "name": "IKE",
            "ikeV1Settings": {"authenticationType": "MANUAL_PRE_SHARED_KEY", "manualPreSharedKey": "manual-secret",
                "policies": [{"id": "ike-v1", "name": "IKEv1 Policy"}]},
            "ikeV2Settings": {"authenticationType": "CERTIFICATE", "automaticPreSharedKeyLength": 7,
                "enforceHexBasedPreSharedKeyOnly": True,
                "certificateAuth": {"id": "cert-1", "name": "VPN Certificate"},
                "policies": [{"id": "ike-v2", "name": "IKEv2 Policy"}]}}],
            "ipsec_settings": [{"id": "ipsec-settings", "name": "IPsec",
                "ikeV1IpsecProposal": [{"id": "proposal-v1", "name": "V1 Proposal"}],
                "ikeV2IpsecProposal": [{"id": "proposal-v2", "name": "V2 Proposal"}],
                "lifetimeSeconds": 28800, "lifetimeKilobytes": 4608000, "ikeV2Mode": "TUNNEL",
                "perfectForwardSecrecy": {"enabled": False}, "cryptoMapType": "STATIC"}],
            "advanced_settings": [{"id": "advanced", "name": "Advanced",
                "advancedIkeSetting": {"peerIdentityValidation": "REQUIRED", "ikeKeepaliveSettings": {
                    "ikeKeepalive": "ENABLED", "retryInterval": 10, "threshold": 5}},
                "advancedTunnelSetting": {"natKeepaliveMessageTraversal": {"enabled": True, "intervalSeconds": 20}}}]}],
        "ikev1policies": [{"id": "ike-v1", "name": "IKEv1 Policy", "priority": 20,
            "lifetimeInSeconds": 86400, "authenticationMethod": "Preshared Key", "encryption": "AES-128",
            "hash": "SHA", "diffieHellmanGroup": 5}],
        "ikev2policies": [{"id": "ike-v2", "name": "IKEv2 Policy", "priority": 12,
            "lifetimeInSeconds": 86400, "encryptionAlgorithms": ["AES-GCM"], "integrityAlgorithms": ["NULL"],
            "prfIntegrityAlgorithms": ["SHA-256"], "diffieHellmanGroups": [14, 19]}],
        "ikev1ipsecproposals": [{"id": "proposal-v1", "name": "V1 Proposal", "espEncryption": "AES-256", "espHash": "SHA-256"}],
        "ikev2ipsecproposals": [{"id": "proposal-v2", "name": "V2 Proposal", "encryptionAlgorithms": ["AES-GCM"],
            "integrityAlgorithms": ["NULL"]}],
    }}
    result = extract_cisco_ftd_source(json.dumps(payload))
    config = result.config

    ikev1, ikev2 = config.ike_policies
    assert (ikev1.ike_version, ikev1.encryption, ikev1.hash, ikev1.diffie_hellman_group,
            ikev1.lifetime_in_seconds, ikev1.priority) == ("IKEv1", "AES-128", "SHA", 5, 86400, 20)
    assert "ike_version" not in ikev1.explicit_fields
    assert (ikev2.encryption_algorithms, ikev2.integrity_algorithms, ikev2.prf_integrity_algorithms,
            ikev2.diffie_hellman_groups) == (["AES-GCM"], ["NULL"], ["SHA-256"], [14, 19])
    v1_proposal, v2_proposal = config.ipsec_proposals
    assert (v1_proposal.esp_encryption, v1_proposal.esp_hash) == ("AES-256", "SHA-256")
    assert (v2_proposal.encryption_algorithms, v2_proposal.integrity_algorithms) == (["AES-GCM"], ["NULL"])
    ike_settings = config.s2s_ike_settings[0]
    assert [ref.source_id for ref in ike_settings.ike_policies] == ["ike-v1", "ike-v2"]
    assert ike_settings.ikev1_authentication_type == "MANUAL_PRE_SHARED_KEY"
    assert ike_settings.ikev2_certificate.source_id == "cert-1"
    assert ike_settings.psk_present is True
    ipsec = config.s2s_ipsec_settings[0]
    assert (ipsec.lifetime_seconds, ipsec.lifetime_kilobytes, ipsec.pfs_enabled, ipsec.ikev2_mode) == (
        28800, 4608000, False, "TUNNEL")
    assert config.s2s_advanced_settings[0].ike_keepalive_settings["retryInterval"] == 10
    before = config.model_dump()
    derived = build_ftd_derived_views(config)
    validate_ftd_config(config, derived)
    resolved_kinds = {item["kind"] for item in derived.resolved_references}
    assert {"IKE_POLICY", "IPSEC_PROPOSAL", "CERTIFICATE", "NETWORK_ADDRESS"} <= resolved_kinds
    assert config.model_dump() == before
    assert derived.vpn_relationships[0]["ike_settings"] == ["IKE"]
    assert derived.vpn_relationships[0]["ipsec_settings"] == ["IPsec"]
    preview_summary = CiscoFTDSourceReporter().build_preview(result)["summary"]
    assert (preview_summary["ikev1_policies"], preview_summary["ikev2_policies"],
            preview_summary["ikev1_ipsec_proposals"], preview_summary["ikev2_ipsec_proposals"]) == (1, 1, 1, 1)
    endpoint = config.s2s_vpn_endpoints[0]
    assert endpoint.protected_networks[0].source_id == "net-1"
    assert (endpoint.local_identity_type, endpoint.local_identity, endpoint.peer_type) == (
        "HOSTNAME", "branch.example", "PEER")

    preview = CiscoFTDSourceReporter().build_preview(result)
    assert "manual-secret" not in json.dumps(preview)
    workbook = BytesIO()
    export_ftd_excel(result, workbook)
    workbook.seek(0)
    values = [value for sheet in load_workbook(workbook, read_only=True).worksheets
              for row in sheet.values for value in row if isinstance(value, str)]
    assert "manual-secret" not in json.dumps(config.model_dump())
    assert "manual-secret" not in " ".join(values)


def test_failed_pbr_collection_remains_failed_when_typed_collection_is_empty():
    payload = {
        "format": "cisco-fmc-rest-export-v1", "collection": {"status": "PARTIAL", "parts": [
            {"name": "device-1/pbr_policies", "status": "FAILED", "complete": False, "count": 0}]},
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {}}],
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    assert result.config.policy_based_routes == []
    assert result.derived.source_plane_completeness["collection:device-1/pbr_policies"] == "failed"
