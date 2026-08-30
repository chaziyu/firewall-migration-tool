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
    assert [response["layer"] for response in responses] == ["parent-uid", "child-uid"]
