import json

import pytest

from tests.checkpoint_fixture_helpers import extract_fixture, fixture
from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


FULL_FIXTURES = [
    "single_gateway_full.json",
    "cluster_full.json",
    "multidomain_full.json",
    "global_policy.json",
    "policy_hierarchy.json",
    "dual_stack.json",
]


@pytest.mark.parametrize("name", FULL_FIXTURES + ["partial_collection.json", "malformed_bundle.json", "legacy_bundle.json"])
def test_checkpoint_fixture_extracts_without_global_failure(name):
    _, result = extract_fixture(name)
    assert result.canonical_ir is not None
    assert result.coverage
    assert result.inventory_items or result.canonical_ir.model_dump()


def test_single_gateway_bundle_has_cross_feature_inventory():
    _, result = extract_fixture("single_gateway_full.json")
    ir = result.canonical_ir
    assert ir.interfaces and ir.routes and ir.addresses and ir.services
    assert ir.certificates
    assert any(item.source_id == "time-1" for item in result.inventory_items)
    assert any(item.source_id == "rule-1" for item in result.inventory_items)
    assert any(item.source_id == "nat-1" for item in result.inventory_items)


def test_cluster_fixture_keeps_vips_members_and_member_local_state():
    _, result = extract_fixture("cluster_full.json")
    cluster = result.canonical_ir.high_availability[0]
    assert cluster.member_references == ["member-1", "member-2"]
    assert cluster.cluster_interfaces[0].virtual_ipv4 == "198.51.100.1"
    assert cluster.member_interface_ips == {"member-1": ["198.51.100.2"], "member-2": ["198.51.100.3"]}
    assert any(item.source_type == "checkpoint-cluster-operational-state" for item in result.inventory_items)


def test_multidomain_fixture_does_not_merge_same_names():
    _, result = extract_fixture("multidomain_full.json")
    assert {address.source_uuid for address in result.canonical_ir.addresses} == {"a-host", "b-host"}
    assert {address.name for address in result.canonical_ir.addresses} == {"SharedName"}
    assert {item.domain for item in result.inventory_items if item.source_id in {"a-host", "b-host"}} == {"Domain-A", "Domain-B"}


def test_dual_stack_fixture_preserves_address_families():
    _, result = extract_fixture("dual_stack.json")
    addresses = {(address.source_uuid, address.address_family): address for address in result.canonical_ir.addresses}
    assert addresses[("v4", "ipv4")].subnet == "192.0.2.40/32"
    assert addresses[("v6", "ipv6")].subnet == "2001:db8::40/128"
    assert addresses[("dual", "ipv4")].subnet == "192.0.2.41/32"
    assert addresses[("dual", "ipv6")].subnet == "2001:db8::41/128"


def test_partial_collection_keeps_empty_distinct_from_failed_collection():
    _, result = extract_fixture("partial_collection.json")
    assert not any(item.source_id for item in result.inventory_items if item.source_path.endswith("show-services-tcp"))
    assert any("UNSUPPORTED_COMMAND" in error or "unsupported" in error.lower() for section in result.coverage for error in section.collection_errors)
    assert any(section.parse_errors for section in result.coverage)


def test_malformed_bundle_isolated_and_visible():
    _, result = extract_fixture("malformed_bundle.json")
    assert any(address.name == "Valid" for address in result.canonical_ir.addresses)
    assert any(item.status.value == "PARSE_ERROR" for item in result.inventory_items)
    assert any("invalid-certificate" in reason for cert in result.canonical_ir.certificates for reason in cert.review_reasons)


def test_legacy_bundle_remains_readable():
    _, result = extract_fixture("legacy_bundle.json")
    assert [address.source_uuid for address in result.canonical_ir.addresses] == ["legacy-host"]


def test_extraction_is_deterministic():
    _, first = extract_fixture("single_gateway_full.json")
    _, second = extract_fixture("single_gateway_full.json")
    assert json.dumps(_without_timestamps(first.model_dump(mode="json")), sort_keys=True) == json.dumps(_without_timestamps(second.model_dump(mode="json")), sort_keys=True)


def _without_timestamps(value):
    if isinstance(value, dict):
        return {key: _without_timestamps(child) for key, child in value.items() if not key.endswith("_at") and "timestamp" not in key}
    if isinstance(value, list):
        return [_without_timestamps(child) for child in value]
    return value


def test_secret_material_is_absent_from_serialized_outputs():
    source = {"responses": [{"command": "show-gateways-and-servers", "data": {"objects": [{"uid": "gw", "name": "gw", "type": "gateway", "password": "fake-password", "sic-password": "fake-sic", "private-key": "fake-key"}]}}]}
    serialized = extract_checkpoint_config(json.dumps(source)).model_dump_json()
    for secret in ("fake-password", "fake-sic", "fake-key"):
        assert secret not in serialized
