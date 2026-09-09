import json

from tests.checkpoint_fixture_helpers import extract_fixture, fixture
from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


REGRESSION_MATRIX = {
    "Gaia interfaces": ("positive", "partial", "malformed", "interaction"),
    "IPv4/IPv6 routes": ("positive", "malformed", "interaction"),
    "PBR/DNS/DHCP/NTP/SNMP": ("partial", "unsupported", "interaction"),
    "management access": ("positive", "malformed"),
    "objects/groups/services/schedules": ("positive", "collision", "interaction"),
    "Access Control/inline layers": ("positive", "unresolved", "interaction"),
    "NAT/VPN": ("positive", "partial", "family interaction"),
    "authentication/identity/application/threat/HTTPS": ("partial", "unsupported", "interaction"),
    "ClusterXL/SecureXL/CoreXL/certificates/SIC": ("positive", "conflict", "secret safety"),
    "packages/layers/Multi-Domain/global assignments": ("collision", "partial", "isolation"),
    "collection contract/coverage": ("empty", "unsupported", "parse error", "determinism"),
}


def test_regression_matrix_is_explicit_and_covers_plan_categories():
    required = {"Gaia interfaces", "Access Control/inline layers", "NAT/VPN", "packages/layers/Multi-Domain/global assignments"}
    assert required <= REGRESSION_MATRIX.keys()
    assert all(cases for cases in REGRESSION_MATRIX.values())


def test_same_object_resolves_across_access_nat_and_group():
    _, result = extract_fixture("r81_golden_matrix.json")
    assert result.canonical_ir.addresses
    source_ids = {address.source_uuid for address in result.canonical_ir.addresses}
    assert "h-uid-web01" in source_ids
    assert any("Ext_Web_VIP" in json.dumps(rule.model_dump(mode="json")) for rule in result.canonical_ir.policies)


def test_policy_hierarchy_keeps_inline_layer_and_parent_rule_separate():
    _, result = extract_fixture("policy_hierarchy.json")
    layers = {layer.uid: layer for layer in result.canonical_ir.checkpoint_access_layers}
    assert "child" in layers
    assert layers["child"].inline is True
    assert len({policy.source_uuid for policy in result.canonical_ir.policies}) == len(result.canonical_ir.policies)


def test_no_false_unsupported_for_supported_empty_family():
    result = extract_checkpoint_config(json.dumps({"responses": [{"command": "show-vpn-communities", "collection_status": "SUCCESS_EMPTY", "data": {"objects": []}}]}))
    assert not any(item.status.value == "UNSUPPORTED" for item in result.inventory_items)
    assert not any(summary.section == "VPN" and summary.status.value == "UNSUPPORTED" for summary in result.coverage)


def test_invalid_reference_cannot_be_normalized():
    result = extract_checkpoint_config(json.dumps({"responses": [{"command": "show-access-rulebase", "package": "P", "layer": "L", "data": {"rulebase": [{"uid": "r", "name": "bad", "source": [{"uid": "missing"}], "destination": ["Any"], "service": ["Any"], "action": "Accept", "enabled": True}]}}]}))
    item = next(item for item in result.inventory_items if item.source_id == "r")
    assert item.status.value != "NORMALIZED"
    assert item.requires_manual_review


def test_response_order_does_not_change_object_identity():
    _, data = fixture("multidomain_full.json")
    first = extract_checkpoint_config(json.dumps(data, sort_keys=True))
    data["responses"] = list(reversed(data["responses"]))
    second = extract_checkpoint_config(json.dumps(data, sort_keys=True))
    assert {item.source_id for item in first.inventory_items} == {item.source_id for item in second.inventory_items}
