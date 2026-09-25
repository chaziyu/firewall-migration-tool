from pathlib import Path
import json
import pytest

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.r81_commands import R81_COMMAND_REGISTRY, canonical_r81_command
from fwmigrate.vendors.checkpoint.loader import canonicalize_command, load_checkpoint_input, validate_pagination
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle, CheckPointResponse
from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config


def test_r81_registry_matches_selected_command_roots_and_scope():
    expected = {
        "show-users", "show-user-groups", "show-permission-profiles", "show-administrators",
        "show-threat-rule-exception-rulebase", "show-vpn-communities-star", "show-vpn-communities-meshed",
    }
    assert expected <= R81_COMMAND_REGISTRY.keys()
    threat = R81_COMMAND_REGISTRY["show-threat-rule-exception-rulebase"]
    assert (threat.scope_type, threat.expected_response_shape) == ("PACKAGE", "rulebase")
    assert canonical_r81_command("show-wildcard-objects") == "show-wildcards"
    assert "show-wildcard-objects" not in R81_COMMAND_REGISTRY
    assert canonicalize_command("show_wildcard_objects") == "show-wildcards"


def test_live_typed_command_contract_and_inventory_boundary():
    typed = {
        "show-users", "show-user-groups", "show-access-roles", "show-permission-profiles", "show-administrators",
        "show-multicast-address-ranges", "show-wildcards", "show-services-sctp", "show-services-icmp6",
        "show-services-citrix-tcp", "show-services-dce-rpc", "show-services-rpc", "show-services-gtp",
        "show-services-compound-tcp", "show-application-sites", "show-application-site-groups",
        "show-application-site-categories", "show-vpn-communities-star", "show-vpn-communities-meshed",
        "show-vpn-communities-remote-access", "show-threat-rule-exception-rulebase",
    }
    for command in typed:
        assert command in R81_COMMAND_REGISTRY
    bundle, _ = load_checkpoint_input(json.dumps({"responses": [{
        "command": "show-wildcard-objects",
        "data": {"objects": [{"uid": "w", "name": "wild", "type": "wildcard"}]},
    }]}))
    assert bundle.responses[0].command == "show-wildcards"
    extracted = extract_checkpoint_config(bundle)
    assert extracted.config.wildcard_addresses and not extracted.source_inventory

    inventory = "show-network-feeds"
    assert inventory in R81_COMMAND_REGISTRY


@pytest.mark.parametrize(
    ("responses", "valid", "reason"),
    [
        ([{"from": 1, "to": 1, "total": 1, "data": {"objects": [{"name": "a"}]}}], True, None),
        ([{"from": 1, "to": 1, "total": 2, "data": {"objects": [{"name": "a"}]}},
          {"from": 2, "to": 2, "total": 2, "data": {"objects": [{"name": "b"}]}}], True, None),
        ([{"from": 1, "to": 0, "total": 0, "data": {"objects": []}}], True, None),
        ([{"from": 1, "total": 1, "data": {"objects": [{"name": "a"}]}}], False, "missing from/to"),
        ([{"from": 1, "to": 1, "total": 1, "data": {"objects": [{"name": "a"}]}},
          {"from": 2, "to": 2, "total": 2, "data": {"objects": [{"name": "b"}]}}], False, "Inconsistent total"),
        ([{"from": 1, "to": 1, "total": 3, "data": {"objects": [{"name": "a"}]}},
          {"from": 3, "to": 3, "total": 3, "data": {"objects": [{"name": "c"}]}}], False, "Gap"),
        ([{"from": 1, "to": 2, "total": 2, "data": {"objects": [{"name": "a"}, {"name": "b"}]}},
          {"from": 2, "to": 2, "total": 2, "data": {"objects": [{"name": "b"}]}}], False, "Overlap"),
        ([{"from": 1, "to": 2, "total": 2, "data": {"objects": [{"name": "a"}]}}], False, "payload count"),
        ([{"from": 1, "to": 1, "total": 2, "data": {"objects": [{"name": "a"}]}}], False, "Incomplete pagination"),
    ],
    ids=["single-page", "multiple-pages", "empty-1-to-0", "missing-range", "inconsistent-totals", "gap", "overlap", "payload-count", "incomplete-final"],
)
def test_pagination_completeness_contract(responses, valid, reason):
    pages = [CheckPointResponse.model_validate({"command": "show-hosts", **response}) for response in responses]
    result, diagnostic = validate_pagination(pages)

    assert result is valid
    if reason is None:
        assert diagnostic is None
    else:
        assert reason.lower() in diagnostic.lower()


def test_paginated_pages_produce_one_operation_diagnostic():
    bundle = CheckPointExportBundle.model_validate({"responses": [
        {"command": "show-hosts", "from": 1, "to": 1, "total": 2, "data": {"objects": [{"type": "host", "name": "a"}]}},
        {"command": "show-hosts", "from": 2, "to": 2, "total": 2, "data": {"objects": [{"type": "host", "name": "b"}]}},
    ]})
    result = extract_checkpoint_config(bundle)

    assert len(result.collection) == 1
    assert result.collection[0].complete is True
    assert [host.name for host in result.config.hosts] == ["a", "b"]


def test_management_bundle_loader_returns_bundle_and_scope():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    bundle, scope = load_checkpoint_input(source)
    assert bundle
    assert scope is not None


def test_scope_selection_is_preserved_in_source_report():
    source = '{"responses": [{"command": "show-hosts", "domain": "A", "data": {"objects": []}}, {"command": "show-hosts", "domain": "B", "data": {"objects": []}}]}'

    result = extract_checkpoint_source(source)

    assert result.scope.ambiguous is True
    assert "multiple-domains-without-selector" in result.scope.reasons


def test_incomplete_collection_is_reported_not_treated_as_empty():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "partial_collection.json").read_text()
    result = extract_checkpoint_source(source)
    assert any(not item.complete for item in result.collection)
    assert any(issue.category == "collection" for issue in result.validation.issues)
