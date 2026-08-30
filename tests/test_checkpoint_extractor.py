import json
import pytest
from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config
from fwmigrate.parsers.checkpoint.loader import load_checkpoint_input
from fwmigrate.parsers.checkpoint.coverage import count_authoritative_source_leaves
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import REDACTED_PLACEHOLDER, sanitize_raw_text
from tests.fixture_paths import CHECKPOINT_FIXTURE


def test_extract_minimal_bundle():
    with open(CHECKPOINT_FIXTURE, "r", encoding="utf-8") as f:
        content = f.read()

    result = extract_checkpoint_config(content)

    assert result.canonical_ir is not None
    assert result.canonical_ir.metadata.hostname == "CP-Enterprise-Gateway"
    assert len(result.source_sections) > 0
    assert len(result.inventory_items) > 0

    # Test Golden Invariant 3: Zero Silent Loss Leaf Accounting
    status_counts = {}
    for item in result.inventory_items:
        status_counts[item.status] = status_counts.get(item.status, 0) + 1

    total_leaf_items = sum(status_counts.values())
    assert total_leaf_items == len(result.inventory_items)
    assert status_counts.get(ExtractionStatus.NORMALIZED, 0) > 0


def test_secret_sanitization_in_extraction():
    bundle_with_secrets = json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [
            {
                "command": "show-gateways-and-servers",
                "data": {
                    "objects": [
                        {
                            "name": "GW01",
                            "type": "simple-gateway",
                            "sic-name": "cn=cp_mgmt,o=myorg",
                            "one-time-password": "SecretPassword123!",
                            "vpn-settings": {
                                "shared-secret": "PresharedKey999!",
                                "token": "SecretSessionToken"
                            }
                        }
                    ]
                }
            }
        ]
    })

    result = extract_checkpoint_config(bundle_with_secrets)
    assert len(result.inventory_items) == 1
    item = result.inventory_items[0]
    attrs = item.source_attributes

    assert attrs.get("one-time-password") == REDACTED_PLACEHOLDER
    assert attrs.get("sic-name") == REDACTED_PLACEHOLDER
    vpn = attrs.get("vpn-settings", {})
    assert vpn.get("shared-secret") == REDACTED_PLACEHOLDER
    assert vpn.get("token") == REDACTED_PLACEHOLDER


def test_unsupported_object_recorded_in_extraction():
    bundle_with_unsupported = json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [
            {
                "command": "show-objects",
                "data": {
                    "objects": [
                        {
                            "uid": "uid-dyn-001",
                            "name": "LocalGatewayDynamic",
                            "type": "dynamic-object",
                            "comments": "dynamic local obj"
                        }
                    ]
                }
            }
        ]
    })

    result = extract_checkpoint_config(bundle_with_unsupported)
    assert len(result.unsupported_items) == 1
    unsupp = result.unsupported_items[0]
    assert unsupp.source_name == "LocalGatewayDynamic"
    assert "dynamic-object" in unsupp.reason
    assert unsupp.requires_manual_review


def test_authoritative_source_leaf_count_matches_inventory():
    content = CHECKPOINT_FIXTURE.read_text(encoding="utf-8")
    bundle, _ = load_checkpoint_input(content)
    result = extract_checkpoint_config(content)
    assert count_authoritative_source_leaves(bundle) == len(result.inventory_items)


def test_incomplete_access_and_nat_pagination_withholds_affected_rulebases():
    bundle = json.dumps({
        "format": "checkpoint-export-v1",
        "selected_package": "Standard",
        "selected_access_layer": "Network",
        "responses": [
            {"command": "show-access-rulebase", "package": "Standard", "layer": "Network",
             "from": 1, "to": 1, "total": 2, "data": {"rulebase": [{
                 "uid": "r1", "rule-number": 1, "source": ["Any"], "destination": ["Any"],
                 "service": ["Any"], "action": "Accept", "enabled": True,
             }]}},
            {"command": "show-nat-rulebase", "package": "Standard",
             "from": 1, "to": 1, "total": 2, "data": {"rulebase": [{
                 "uid": "n1", "rule-number": 1, "original-source": "Any",
                 "original-destination": "Any", "original-service": "Any",
                 "translated-source": "Any", "translated-destination": "Original",
                 "translated-service": "Original", "enabled": True,
             }]}},
        ],
    })
    result = extract_checkpoint_config(bundle)
    assert result.canonical_ir.policies == []
    assert result.canonical_ir.nat_rules == []
    rule_items = [i for i in result.inventory_items if i.source_type in {"access-rule", "nat-rule"}]
    assert len(rule_items) == 2
    assert all("incomplete-pagination" in item.notes for item in rule_items)


def test_canonical_ir_source_evidence_is_sanitized():
    secret_password = "CanonicalPassword-123"
    secret_psk = "CanonicalPSK-456"
    bundle = json.dumps({
        "format": "checkpoint-export-v1",
        "selected_package": "Standard", "selected_access_layer": "Network",
        "responses": [{
            "command": "show-access-rulebase", "package": "Standard", "layer": "Network",
            "data": {"rulebase": [{
                "uid": "r-secret", "rule-number": 1, "source": ["Any"],
                "destination": ["Any"], "service": ["Any"], "action": "Accept",
                "enabled": True, "source-settings": {
                    "password": secret_password, "shared-secret": secret_psk,
                },
            }]},
        }],
    })
    serialized = extract_checkpoint_config(bundle).model_dump_json()
    assert secret_password not in serialized
    assert secret_psk not in serialized
    assert REDACTED_PLACEHOLDER in serialized


def test_ambiguous_domain_scope_accounts_rules_without_canonical_merge():
    responses = []
    for domain in ("Domain-A", "Domain-B"):
        responses.append({
            "command": "show-access-rulebase", "domain": domain,
            "package": "Standard", "layer": "Network",
            "data": {"rulebase": [{
                "uid": f"rule-{domain}", "rule-number": 1, "source": ["Any"],
                "destination": ["Any"], "service": ["Any"], "action": "Accept", "enabled": True,
            }]},
        })
    result = extract_checkpoint_config(json.dumps({
        "format": "checkpoint-export-v1", "responses": responses,
    }))
    assert result.canonical_ir.policies == []
    rules = [item for item in result.inventory_items if item.source_type == "access-rule"]
    assert len(rules) == 2
    assert all("multiple-domains-without-selector" in item.notes for item in rules)


@pytest.mark.parametrize("line,secret", [
    ('set user admin password "quoted secret value"', "quoted secret value"),
    ("set user admin password-hash   '$6$synthetic-hash'", "$6$synthetic-hash"),
    ('set vpn shared-secret "synthetic psk"', "synthetic psk"),
    ('set sic one-time-password   "synthetic otp"', "synthetic otp"),
])
def test_raw_gaia_secret_patterns_are_redacted(line, secret):
    sanitized = sanitize_raw_text(line)
    assert secret not in sanitized
    assert REDACTED_PLACEHOLDER in sanitized


def test_automatic_nat_intent_without_rulebase_is_explicit_and_not_synthesized():
    result = extract_checkpoint_config(json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [{"command": "show-hosts", "data": {"objects": [{
            "uid": "auto-nat-host", "name": "AutoNAT", "type": "host",
            "ipv4-address": "10.0.0.10", "nat-settings": {
                "auto-rule": True, "method": "hide", "ipv4-address": "198.51.100.10",
            },
        }]}}],
    }))
    assert result.canonical_ir.nat_rules == []
    item = next(i for i in result.inventory_items if i.source_id == "auto-nat-host")
    assert item.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert "automatic-nat-intent-without-complete-nat-rulebase" in item.notes
    assert any("automatic-nat-intent" in unsupported.reason for unsupported in result.unsupported_items)


def test_objects_dictionary_only_entries_are_authoritatively_accounted():
    fixture = CHECKPOINT_FIXTURE.parent / "rulebase_dictionary_only.json"
    content = fixture.read_text(encoding="utf-8")
    bundle, _ = load_checkpoint_input(content)
    result = extract_checkpoint_config(content)

    by_id = {item.source_id: item for item in result.inventory_items}
    assert {"dict-host", "dict-service", "dict-action",
            "97aeb369-9aea-11d5-bd16-0090272ccb30"}.issubset(by_id)
    assert by_id["dict-host"].status == ExtractionStatus.NORMALIZED
    assert by_id["dict-service"].status == ExtractionStatus.NORMALIZED
    assert by_id["dict-action"].status == ExtractionStatus.EXTRACT_ONLY
    assert len(result.canonical_ir.policies) == 1
    assert result.canonical_ir.policies[0].source == ["DictionaryHost"]
    assert result.canonical_ir.policies[0].service == ["DictionaryHTTPS"]
    assert count_authoritative_source_leaves(bundle) == len(result.inventory_items)


def test_objects_dictionary_duplicate_uid_is_counted_once_with_provenance():
    any_uid = "97aeb369-9aea-11d5-bd16-0090272ccb30"
    content = json.dumps({
        "format": "checkpoint-export-v1",
        "selected_package": "Standard",
        "selected_access_layer": "Network",
        "responses": [{
            "command": "show-hosts",
            "data": {"objects": [{
                "uid": "uid-1", "name": "DedicatedHost", "type": "host",
                "ipv4-address": "10.0.0.1",
            }]},
        }, {
            "command": "show-access-rulebase", "package": "Standard", "layer": "Network",
            "data": {
                "objects-dictionary": [{
                    "uid": "uid-1", "name": "DedicatedHost", "type": "host",
                    "ipv4-address": "10.0.0.1",
                }, {
                    "uid": "action", "name": "Accept", "type": "RulebaseAction",
                }, {
                    "uid": any_uid, "name": "Any", "type": "CpmiAnyObject",
                }],
                "rulebase": [{
                    "uid": "rule", "rule-number": 1, "type": "access-rule",
                    "source": ["uid-1"], "destination": [any_uid], "service": [any_uid],
                    "action": "action", "vpn": any_uid, "enabled": True,
                }],
            },
        }],
    })
    bundle, _ = load_checkpoint_input(content)
    result = extract_checkpoint_config(content)
    host_items = [item for item in result.inventory_items if item.source_id == "uid-1"]
    assert len(host_items) == 1
    assert any(ref.startswith("objects-dictionary:show-access-rulebase")
               for ref in host_items[0].source_references)
    assert count_authoritative_source_leaves(bundle) == len(result.inventory_items)


def test_dictionary_evidence_provenance_and_malformed_identity_are_exact():
    content = json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [{
            "command": "show-access-rulebase", "package": "Standard", "layer": "Network",
            "data": {
                "objects-dictionary": [
                    {"uid": "action", "name": "Accept", "type": "RulebaseAction"},
                    "malformed-entry",
                ],
                "rulebase": [],
            },
        }, {
            "command": "show-nat-rulebase", "package": "Standard",
            "data": {
                "objects-dictionary": [
                    {"uid": "action", "name": "Accept", "type": "RulebaseAction"},
                ],
                "rulebase": [],
            },
        }],
    })
    bundle, _ = load_checkpoint_input(content)
    result = extract_checkpoint_config(content)
    assert count_authoritative_source_leaves(bundle) == len(result.inventory_items) == 2
    action = next(item for item in result.inventory_items if item.source_id == "action")
    malformed = next(item for item in result.inventory_items if item.source_type == "malformed-objects-dictionary-entry")
    assert len(action.source_references) == 2
    assert malformed.status == ExtractionStatus.PARSE_ERROR


def test_management_security_zone_and_gateway_topology_reach_ir():
    content = json.dumps({
        "format": "checkpoint-export-v1", "responses": [
            {"command": "show-security-zones", "data": {"objects": [{
                "uid": "zone-in", "name": "InternalZone", "type": "security-zone",
            }]}},
            {"command": "show-gateways-and-servers", "data": {"objects": [{
                "uid": "gw", "name": "GW", "type": "simple-gateway",
                "interfaces": [{
                    "name": "eth0", "ipv4-address": "10.0.0.1",
                    "ipv4-network-mask": "255.255.255.0", "topology": "internal",
                    "anti-spoofing": True, "security-zone": "zone-in",
                }],
            }]}},
        ],
    })
    result = extract_checkpoint_config(content)
    zone = next(item for item in result.canonical_ir.zones if item.name == "InternalZone")
    interface = next(item for item in result.canonical_ir.interfaces if item.name == "eth0")
    assert interface.zone == "InternalZone"
    assert interface.ip == "10.0.0.1/24"
    assert zone.interfaces == ["eth0"]
    zone_item = next(item for item in result.inventory_items if item.source_id == "zone-in")
    assert zone_item.status == ExtractionStatus.NORMALIZED


def test_section_normalized_count_uses_final_inventory_status():
    result = extract_checkpoint_config(json.dumps({
        "format": "checkpoint-export-v1", "selected_package": "Standard",
        "selected_access_layer": "Network", "responses": [{
            "command": "show-access-rulebase", "package": "Standard", "layer": "Network",
            "data": {"rulebase": [{
                "uid": "ask", "rule-number": 1, "type": "access-rule",
                "source": ["Any"], "destination": ["Any"], "service": ["Any"],
                "vpn": "Any", "time": ["Any"], "action": "Ask", "enabled": True,
            }]},
        }],
    }))
    section = next(item for item in result.source_sections if "show-access-rulebase" in item.path)
    assert section.object_count_source == 1
    assert section.object_count_normalized == 0
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert result.requires_manual_review
    assert not result.generation_safe


def test_gaia_management_interface_conflict_is_preserved_for_review():
    result = extract_checkpoint_config(json.dumps({
        "format": "checkpoint-export-v1", "responses": [
            {"command": "gaia/show-configuration", "data": {
                "cli_text": "set interface eth0 ipv4-address 10.0.0.1 mask-length 24",
            }},
            {"command": "show-gateways-and-servers", "data": {"objects": [{
                "uid": "gw", "name": "GW", "type": "simple-gateway", "interfaces": [{
                    "name": "eth0", "ipv4-address": "192.0.2.1",
                    "ipv4-network-mask": "255.255.255.0", "topology": "external",
                }],
            }]}},
        ],
    }))
    interface = result.canonical_ir.interfaces[0]
    assert interface.ip == "10.0.0.1/24"
    assert interface.source_attributes["checkpoint-management-topology"]["ipv4-address"] == "192.0.2.1"
    assert interface.requires_manual_review
    assert "gaia-management-ip-conflict" in interface.parse_errors
    assert not result.generation_safe
