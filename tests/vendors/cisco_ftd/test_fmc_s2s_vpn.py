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
    derived = build_ftd_derived_views(config)
    validate_ftd_config(config, derived)
    resolved_kinds = {item["kind"] for item in derived.resolved_references}
    assert {"IKE_POLICY", "IPSEC_PROPOSAL", "CERTIFICATE", "NETWORK_ADDRESS"} <= resolved_kinds
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
    assert "manual-secret" not in json.dumps(config.model_dump())
