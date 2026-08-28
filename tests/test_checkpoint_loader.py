import json
import pytest
from fwmigrate.parsers.checkpoint.loader import (
    canonicalize_command,
    load_checkpoint_input,
    group_response_pages,
    validate_pagination,
)
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.errors import CheckPointParseError
from tests.fixture_paths import CHECKPOINT_FIXTURE, CHECKPOINT_AMBIGUOUS_FIXTURE


def test_canonicalize_command():
    assert canonicalize_command("show hosts") == "show-hosts"
    assert canonicalize_command("show_hosts") == "show-hosts"
    assert canonicalize_command("SHOW-HOSTS") == "show-hosts"
    assert canonicalize_command("  show-access-rulebase  ") == "show-access-rulebase"
    assert canonicalize_command("show   nat   rulebase") == "show-nat-rulebase"


def test_load_minimal_bundle():
    with open(CHECKPOINT_FIXTURE, "r", encoding="utf-8") as f:
        content = f.read()

    bundle, scope = load_checkpoint_input(content)
    assert bundle.format == "checkpoint-export-v1"
    assert len(bundle.responses) == 7
    assert scope.selected_domain == "SMC User"
    assert scope.selected_package == "Standard"
    assert scope.selected_access_layer == "Network"
    assert not scope.ambiguous


def test_ambiguous_top_level_rulebase_rejected():
    with open(CHECKPOINT_AMBIGUOUS_FIXTURE, "r", encoding="utf-8") as f:
        content = f.read()

    with pytest.raises(CheckPointParseError, match="Ambiguous Check Point rulebase"):
        load_checkpoint_input(content)


def test_legacy_unambiguous_access_and_nat_rulebase():
    legacy_json = json.dumps({
        "name": "GW01",
        "objects": [{"type": "host", "name": "H1", "ipv4-address": "1.1.1.1"}],
        "access-rulebase": [{"rule-number": 1, "name": "R1", "action": "Accept"}],
        "nat-rulebase": [{"rule-number": 1, "name": "N1"}]
    })

    bundle, scope = load_checkpoint_input(legacy_json)
    cmds = [r.command for r in bundle.responses]
    assert "show-objects" in cmds
    assert "show-access-rulebase" in cmds
    assert "show-nat-rulebase" in cmds
    assert not scope.ambiguous


def test_multiple_packages_without_selector_is_ambiguous():
    multi_pkg_bundle = json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [
            {
                "command": "show-access-rulebase",
                "package": "Pkg_Corp",
                "layer": "Network",
                "data": {"rulebase": []}
            },
            {
                "command": "show-access-rulebase",
                "package": "Pkg_Branch",
                "layer": "Network",
                "data": {"rulebase": []}
            }
        ]
    })

    bundle, scope = load_checkpoint_input(multi_pkg_bundle)
    assert scope.ambiguous
    assert "multiple-packages-without-selector" in scope.reasons


def test_group_response_pages():
    responses = [
        CheckPointResponse(command="show-hosts", domain="D1", data={"objects": []}),
        CheckPointResponse(command="show-hosts", domain="D1", data={"objects": []}),
        CheckPointResponse(command="show-networks", domain="D1", data={"objects": []}),
    ]
    grouped = group_response_pages(responses)
    assert len(grouped) == 2
    assert len(grouped[("show-hosts", "D1", None, None, None)]) == 2
    assert len(grouped[("show-networks", "D1", None, None, None)]) == 1


def test_validate_pagination_contiguous():
    pages = [
        CheckPointResponse(command="show-hosts", data={"from": 1, "to": 50, "total": 100}),
        CheckPointResponse(command="show-hosts", data={"from": 51, "to": 100, "total": 100}),
    ]
    for p in pages:
        p.from_index = p.data["from"]
        p.to_index = p.data["to"]
        p.total = p.data["total"]

    valid, reason = validate_pagination(pages)
    assert valid
    assert reason is None


def test_validate_pagination_missing_middle_page():
    pages = [
        CheckPointResponse(command="show-hosts", data={"from": 1, "to": 50, "total": 150}),
        CheckPointResponse(command="show-hosts", data={"from": 101, "to": 150, "total": 150}),
    ]
    for p in pages:
        p.from_index = p.data["from"]
        p.to_index = p.data["to"]
        p.total = p.data["total"]

    valid, reason = validate_pagination(pages)
    assert not valid
    assert "Gap in pagination" in str(reason)


def test_validate_pagination_incomplete_end():
    pages = [
        CheckPointResponse(command="show-hosts", data={"from": 1, "to": 50, "total": 100}),
    ]
    for p in pages:
        p.from_index = p.data["from"]
        p.to_index = p.data["to"]
        p.total = p.data["total"]

    valid, reason = validate_pagination(pages)
    assert not valid
    assert "Incomplete pagination" in str(reason)


def test_validate_pagination_total_mismatch():
    pages = [
        CheckPointResponse(command="show-hosts", data={"from": 1, "to": 50, "total": 100}),
        CheckPointResponse(command="show-hosts", data={"from": 51, "to": 100, "total": 120}),
    ]
    for p in pages:
        p.from_index = p.data["from"]
        p.to_index = p.data["to"]
        p.total = p.data["total"]

    valid, reason = validate_pagination(pages)
    assert not valid
    assert "Inconsistent total counts" in str(reason)
