from pathlib import Path
import json

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.r81_commands import R81_COMMAND_REGISTRY, canonical_r81_command
from fwmigrate.vendors.checkpoint.loader import canonicalize_command
from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input
from fwmigrate.vendors.checkpoint.extraction.objects import _COMMAND_DISPATCH
from fwmigrate.vendors.checkpoint.extraction.extractor import _POLICY_EXTRACTORS


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
        assert command in (_COMMAND_DISPATCH.keys() | _POLICY_EXTRACTORS.keys())
    inventory = "show-network-feeds"
    assert inventory in R81_COMMAND_REGISTRY and inventory not in _COMMAND_DISPATCH and inventory not in _POLICY_EXTRACTORS

    bundle, _ = load_checkpoint_input(json.dumps({"responses": [{
        "command": "show-wildcard-objects",
        "data": {"objects": [{"uid": "w", "name": "wild", "type": "wildcard"}]},
    }]}))
    assert bundle.responses[0].command == "show-wildcards"
    from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
    extracted = extract_checkpoint_config(bundle)
    assert extracted.config.wildcard_addresses and not extracted.source_inventory


def test_incomplete_collection_is_reported_not_treated_as_empty():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "partial_collection.json").read_text()
    result = extract_checkpoint_source(source)
    assert any(not item.complete for item in result.collection)
    assert any(issue.category == "collection" for issue in result.validation.issues)
