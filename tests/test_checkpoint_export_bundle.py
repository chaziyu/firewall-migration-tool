"""Unit coverage for Check Point Management bundle discovery helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "export_checkpoint_bundle.py"
SPEC = importlib.util.spec_from_file_location("export_checkpoint_bundle", SCRIPT)
assert SPEC and SPEC.loader
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def test_collection_manifest_contains_verified_r81_families():
    commands = {command for group in collector.COLLECTION_MANIFEST.values() for command, _ in group}
    assert {
        "show-wildcards", "show-multicast-address-ranges", "show-dynamic-objects",
        "show-dns-domains", "show-network-feeds", "show-checkpoint-hosts",
        "show-interoperable-devices", "show-updatable-objects", "show-data-center-objects",
        "show-services-citrix-tcp", "show-services-dce-rpc", "show-services-rpc",
        "show-services-gtp", "show-services-compound-tcp", "show-access-layers",
    }.issubset(commands)


def test_package_layer_discovery_uses_authoritative_layer_uid():
    responses = [{
        "command": "show-packages", "data": {"objects": [{
            "name": "Standard", "access-layers": [{"uid": "layer-uid", "name": "Network"}],
        }]},
    }, {
        "command": "show-access-layers", "data": {"objects": [{
            "uid": "layer-uid", "name": "Network",
        }]},
    }]
    assert collector._discover_package_layers(responses, None, None) == [
        ("Standard", "Network", "layer-uid"),
    ]


def test_inline_layer_collection_is_recursive_and_loop_safe(monkeypatch):
    calls = []

    def fake_collect(command, payload, session_id=None, **scope):
        calls.append(payload["name"])
        if payload["name"] == "parent-uid":
            rulebase = [{
                "uid": "parent-rule",
                "inline-layer": {"uid": "child-uid", "name": "Child"},
            }]
        else:
            rulebase = [{
                "uid": "child-rule",
                "inline-layer": {"uid": "parent-uid", "name": "Parent"},
            }]
        return [{"command": command, **scope, "data": {"rulebase": rulebase}}]

    monkeypatch.setattr(collector, "collect_paginated", fake_collect)
    responses = collector.collect_access_layer_tree("Standard", "Parent", "parent-uid", None)
    assert calls == ["parent-uid", "child-uid"]
    assert [response["layer"] for response in responses] == ["Parent", "Child"]
    assert [response["layer_uid"] for response in responses] == ["parent-uid", "child-uid"]
    assert responses[1]["parent_layer"] == "Parent"
    assert responses[1]["parent_layer_uid"] == "parent-uid"
    assert responses[1]["parent_rule_uid"] == "parent-rule"
    assert responses[1]["collection_warnings"] == [
        "inline-layer-cycle-or-duplicate:parent-uid",
    ]


def test_paginated_collection_distinguishes_data_from_legitimate_empty(monkeypatch):
    payloads = [
        {"objects": [{"uid": "one"}], "from": 1, "to": 1, "total": 1},
        {"objects": [], "from": 1, "to": 0, "total": 0},
    ]
    monkeypatch.setattr(collector, "run_mgmt_cli", lambda *_args, **_kwargs: payloads.pop(0))

    with_data = collector.collect_paginated("show-hosts", {"limit": 500})[0]
    empty = collector.collect_paginated("show-networks", {"limit": 500})[0]

    assert with_data["collection_status"] == collector.SUCCESS_WITH_DATA
    assert with_data["object_count"] == 1
    assert empty["collection_status"] == collector.SUCCESS_EMPTY
    assert empty["object_count"] == 0


def test_command_failure_states_are_distinct_and_sanitized():
    assert collector._error_details('{"code":"generic_err_command_not_found","message":"Unknown command"}')[:2] == (
        collector.UNSUPPORTED_COMMAND, "generic_err_command_not_found",
    )
    assert collector._error_details("Permission denied")[0] == collector.PERMISSION_DENIED
    status, _, message = collector._error_details("API error token=top-secret")
    assert status == collector.API_ERROR
    assert "top-secret" not in message


def test_missing_mgmt_cli_is_transport_error(monkeypatch):
    def missing(*_args, **_kwargs):
        raise FileNotFoundError("mgmt_cli was not found")

    monkeypatch.setattr(collector.subprocess, "run", missing)
    result = collector.run_mgmt_cli("show-hosts", {})
    assert result["collection_status"] == collector.TRANSPORT_ERROR


def test_collection_completeness_is_command_and_scope_specific():
    responses = [
        {"command": "show-nat-rulebase", "domain": "D1", "package": "A",
         "collection_status": collector.SUCCESS_EMPTY, "object_count": 0},
        {"command": "show-nat-rulebase", "domain": "D1", "package": "B",
         "collection_status": collector.API_ERROR, "collection_error_code": "generic_err",
         "error": "failed", "data": {}},
    ]
    completeness = collector.build_collection_completeness(responses)
    assert completeness["show-nat-rulebase|domain=D1|package=A"]["complete"] is True
    assert completeness["show-nat-rulebase|domain=D1|package=A"]["status"] == collector.SUCCESS_EMPTY
    assert completeness["show-nat-rulebase|domain=D1|package=B"]["complete"] is False
    assert completeness["show-nat-rulebase|domain=D1|package=B"]["status"] == collector.API_ERROR
