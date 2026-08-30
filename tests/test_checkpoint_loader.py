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
    access = next(r for r in bundle.responses if r.command == "show-access-rulebase")
    nat = next(r for r in bundle.responses if r.command == "show-nat-rulebase")
    assert access.package == "Standard"
    assert access.layer == "Network"
    assert access.data["rulebase"][0]["vpn"] == "Any"
    assert nat.package == "Standard"


def test_command_aware_missing_scope_is_not_fabricated():
    bundle, scope = load_checkpoint_input(json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [{
            "command": "show-access-rulebase",
            "data": {"rulebase": []},
        }, {
            "command": "show-nat-rulebase",
            "data": {"rulebase": []},
        }],
    }))
    access = next(r for r in bundle.responses if r.command == "show-access-rulebase")
    nat = next(r for r in bundle.responses if r.command == "show-nat-rulebase")
    assert access.package is None
    assert access.layer is None
    assert nat.package is None
    assert scope.selected_package is None
    assert scope.selected_access_layer is None


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


def test_validate_pagination_overlap():
    pages = [
        CheckPointResponse(command="show-hosts", **{"from": 1, "to": 50, "total": 100}),
        CheckPointResponse(command="show-hosts", **{"from": 40, "to": 100, "total": 100}),
    ]
    valid, reason = validate_pagination(pages)
    assert not valid
    assert "Overlap in pagination" in str(reason)


def test_validate_pagination_rejects_to_greater_than_total():
    valid, reason = validate_pagination([
        CheckPointResponse(command="show-hosts", **{"from": 1, "to": 2, "total": 1}),
    ])
    assert not valid
    assert "exceeds total" in str(reason)


def test_validate_pagination_rejects_from_less_than_one():
    valid, reason = validate_pagination([
        CheckPointResponse(command="show-hosts", **{"from": 0, "to": 1, "total": 1}),
    ])
    assert not valid
    assert "less than 1" in str(reason)


def test_validate_object_pagination_payload_count():
    valid, reason = validate_pagination([
        CheckPointResponse(
            command="show-hosts", **{"from": 1, "to": 2, "total": 2},
            data={"objects": [{"uid": "one"}]},
        ),
    ])
    assert not valid
    assert reason == "Pagination metadata does not match payload count"


def test_rulebase_pagination_does_not_compare_section_container_count():
    page = CheckPointResponse(
        command="show-access-rulebase", **{"from": 1, "to": 2, "total": 2},
        data={"rulebase": [{
            "type": "access-section", "name": "Section", "rulebase": [
                {"uid": "one"}, {"uid": "two"},
            ],
        }]},
    )
    assert validate_pagination([page]) == (True, None)


def test_rulebase_truncated_native_page_is_incomplete():
    page = CheckPointResponse(
        command="show-access-rulebase", **{"from": 1, "to": 100, "total": 100},
        data={"rulebase": [{"uid": str(index)} for index in range(75)]},
    )
    valid, reason = validate_pagination([page])
    assert not valid
    assert "native payload count" in reason


def test_multiple_unpaged_responses_are_ambiguous():
    pages = [CheckPointResponse(command="show-hosts", data={"objects": []}) for _ in range(2)]
    assert validate_pagination(pages) == (
        False, "multiple-unpaged-responses-without-pagination-metadata",
    )
