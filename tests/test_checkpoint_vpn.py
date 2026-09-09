import json

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def test_checkpoint_vpn_communities_and_gateway_properties_are_extracted():
    result = extract_checkpoint_config(json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [
            {"command": "show-vpn-communities-star", "domain": "D1", "data": {"objects": [{
                "uid": "comm-1", "name": "BranchVPN", "center-gateways": ["gw-1"],
                "satellite-gateways": ["gw-2"], "ike-version": "ikev2",
                "encryption-algorithm": "aes-256", "hash": "sha256",
                "dh-group": "14", "lifetime": "3600", "pfs": "group14",
                "shared-secret-reference": {"uid": "secret-ref-1"},
            }]}},
            {"command": "show-gateways-and-servers", "domain": "D1", "data": {"objects": [{
                "uid": "gw-1", "name": "GW1", "ipv4-address": "198.51.100.1",
                "vpn-settings": {"enabled": True, "communities": [{"uid": "comm-1"}]},
            }]}},
        ],
    }))

    community = result.canonical_ir.vpn_communities[0]
    gateway = result.canonical_ir.vpn_gateways[0]
    assert community.uid == "comm-1"
    assert community.center_gateways == ["gw-1"]
    assert community.shared_secret_reference == "secret-ref-1"
    assert gateway.main_ip == "198.51.100.1"
    assert gateway.community_membership == ["comm-1"]


def test_checkpoint_gaia_authentication_is_secret_safe():
    result = extract_checkpoint_config("set user alice password 'do-not-export' role admin\n")
    assert result.canonical_ir.local_users[0].name == "alice"
    serialized = result.model_dump_json()
    assert "do-not-export" not in serialized
