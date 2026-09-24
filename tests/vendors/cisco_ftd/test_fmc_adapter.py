import json
from io import BytesIO
from pathlib import Path
from openpyxl import load_workbook

from fwmigrate.vendors.cisco_ftd.fmc.fmc_adapter import CiscoFMCBundleParser
from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter, extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views
from fwmigrate.vendors.cisco_ftd.validation import validate_ftd_config
from fwmigrate.vendors.cisco_ftd.export.excel import export_ftd_excel


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"


def test_selected_fmc_domains_preserve_native_ownership_and_order():
    config = CiscoFMCBundleParser(FIXTURE.read_text(encoding="utf-8")).parse_source()
    assert [x.name for x in config.time_ranges] == ["business-hours"]
    assert config.network_addresses[0].raw_extra["type"] == "FQDN"
    assert config.access_control_policies[0].rules[0].source_zones[0].name == "inside"
    assert config.access_control_policies[0].rules[0].destination_zones[0].name == "outside"
    assert config.intrusion_rule_overrides[0].source_attributes["parent_policy_id"] == "ips-1"
    assert config.s2s_vpn_endpoints[0].source_attributes["parent_topology_id"] == "vpn-1"
    assert config.ra_vpn_connection_profiles[0].source_attributes["parent_policy_id"] == "ra-1"
    assert config.routes[0].source_attributes["device_name"] == "FTD-A"
    assert config.dhcp_servers[0].source_attributes["device_id"] == "device-1"
    assert config.file_policies[0].raw_extra["rules"][0]["order"] == 1


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
                "static_routes": [{"id": "vr-route", "name": "vr-route"}],
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


def test_failed_pbr_collection_remains_failed_when_typed_collection_is_empty():
    payload = {
        "format": "cisco-fmc-rest-export-v1", "collection": {"status": "PARTIAL", "parts": [
            {"name": "device-1/pbr_policies", "status": "FAILED", "complete": False, "count": 0}]},
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {}}],
    }
    result = extract_cisco_ftd_source(json.dumps(payload))
    assert result.config.policy_based_routes == []
    assert result.derived.source_plane_completeness["collection:device-1/pbr_policies"] == "failed"
