from dataclasses import replace
import json

import pytest

from fwmigrate.conversion.fortigate_to_checkpoint.application.workflow import (
    approve_design, build_artifact, build_review,
)
from fwmigrate.conversion.fortigate_to_checkpoint.target.evidence import FAMILIES
from fwmigrate.vendors.checkpoint.source_report import CheckPointSourceReporter


def target_snapshot(plan, options):
    responses = []
    groups = {}
    for item in plan.items:
        operation = dict(item.settings).get("management_operation")
        if item.family not in {"address", "address6", "service"} or item.blockers or not operation:
            continue
        body = operation["request_body_template"]
        kind = operation["path"].removeprefix("/web_api/add-")
        command = {"host": "show-hosts", "network": "show-networks", "address-range": "show-address-ranges", "service-tcp": "show-services-tcp", "service-udp": "show-services-udp"}[kind]
        obj = {**body, "type": kind, "uid": "uid-" + item.target_name}
        if item.family in {"address", "address6"}:
            obj["nat-settings"] = {"auto-rule": False}
        else:
            obj.setdefault("source-port", "1-65535")
        groups.setdefault(command, []).append(obj)
    for command, objects in groups.items():
        responses.append({"command": command, "domain": options.management_domain,
                          "data": {"objects": objects, "from": 1, "to": len(objects), "total": len(objects)}})
    return {"format": "checkpoint-export-v1", "api_version": "1.8.1",
            "management_server": options.management_target, "domain": options.management_domain,
            "selected_domain": options.management_domain, "responses": responses}


def destination(snapshot, options):
    text = json.dumps(snapshot)
    return {"target": CheckPointSourceReporter().analyze_source(text), "target_source_text": text,
            "target_metadata": {"context": options.management_domain, "version": "1.8.1",
                                "mode": "management", "complete_families": sorted(FAMILIES)}}


def with_cleanup(snapshot, options):
    rows = [
        ("show-packages", {"uid": "package", "name": options.policy_package, "type": "package",
                           "access-layers": [{"uid": "layer", "name": options.access_layer}]}),
        ("show-access-layers", {"uid": "layer", "name": options.access_layer, "type": "access-layer"}),
        ("show-simple-gateways", {"uid": "gateway", "name": options.install_on[0], "type": "simple-gateway"}),
    ]
    for command, obj in rows:
        snapshot["responses"].append({"command": command, "domain": options.management_domain,
                                      "data": {"objects": [obj], "from": 1, "to": 1, "total": 1}})
    cleanup = {"uid": "cleanup", "name": options.insertion_anchor, "type": "access-rule", "rule-number": 1,
               "enabled": True, "action": {"name": "Drop"}, "source-negate": False, "destination-negate": False,
               "install-on": [{"name": options.install_on[0]}],
               **{field: [{"name": "Any"}] for field in ("source", "destination", "service", "time", "vpn", "content")}}
    snapshot["responses"].append({"command": "show-access-rulebase", "domain": options.management_domain,
                                  "package": options.policy_package, "package_uid": "package",
                                  "layer": options.access_layer, "layer_uid": "layer",
                                  "data": {"rulebase": [cleanup], "from": 1, "to": 1, "total": 1}})
    return snapshot


def test_exact_native_objects_reuse_without_creation(checkpoint_analysis, checkpoint_options):
    baseline = build_review(checkpoint_analysis, checkpoint_options, "source")
    evidence = destination(target_snapshot(baseline["plan"], checkpoint_options), checkpoint_options)
    review = build_review(checkpoint_analysis, checkpoint_options, "source", **evidence)
    reused = [item for item in review["report"]["items"] if item["render_disposition"] == "REUSE"]
    assert reused
    assert {item["family"] for item in reused} == {"address", "service"}
    assert len(reused) == sum(item.family in {"address", "service"} and not item.blockers for item in baseline["plan"].items)
    selected = [item["key"] for item in reused]
    approval = approve_design(review, review["draft"], selected)
    artifact = build_artifact(checkpoint_analysis, checkpoint_options, "source", approval, **evidence)
    assert artifact["report"]["management_operation_count"] == 0
    assert artifact["report"]["destination_snapshot_compared"]
    assert artifact["target_digest"] == approval["target_digest"]
    changed = {**evidence, "target_metadata": {**evidence["target_metadata"], "complete_families": ["objects"]}}
    with pytest.raises(ValueError, match="approval"):
        build_artifact(checkpoint_analysis, checkpoint_options, "source", approval, **changed)


def test_destination_collision_incomplete_and_wrong_scope_fail_closed(checkpoint_analysis, checkpoint_options):
    baseline = build_review(checkpoint_analysis, checkpoint_options, "source")
    snapshot = target_snapshot(baseline["plan"], checkpoint_options)
    snapshot["responses"][0]["data"]["objects"][0]["nat-settings"] = {"auto-rule": True}
    review = build_review(checkpoint_analysis, checkpoint_options, "source", **destination(snapshot, checkpoint_options))
    assert any("TARGET_OBJECT_COLLISION_OR_EQUIVALENCE_UNKNOWN" in item.blockers for item in review["plan"].items)
    snapshot["responses"][0]["data"]["total"] = 100
    with pytest.raises(ValueError):
        build_review(checkpoint_analysis, checkpoint_options, "source", **destination(snapshot, checkpoint_options))
    snapshot = target_snapshot(baseline["plan"], checkpoint_options)
    evidence = destination(snapshot, checkpoint_options)
    with pytest.raises(ValueError, match="scope"):
        build_review(checkpoint_analysis, replace(checkpoint_options, management_domain="Other"), "source", **evidence)


def test_reused_uids_feed_rule_requests_and_cleanup_placement(checkpoint_analysis, checkpoint_options):
    baseline = build_review(checkpoint_analysis, checkpoint_options, "source")
    snapshot = with_cleanup(target_snapshot(baseline["plan"], checkpoint_options), checkpoint_options)
    evidence = destination(snapshot, checkpoint_options)
    review = build_review(checkpoint_analysis, checkpoint_options, "source", **evidence)
    policies = [item for item in review["report"]["items"] if item["family"] == "policy"]
    assert all(item["render_disposition"] == "CREATE" for item in policies), policies
    approval = approve_design(review, review["draft"], [item["key"] for item in policies])
    artifact = build_artifact(checkpoint_analysis, checkpoint_options, "source", approval, **evidence)
    operations = json.loads(artifact["files"]["checkpoint_management_operations.json"]["content"])["operations"]
    assert len(operations) == 2
    assert operations[0]["request_body_template"]["position"] == {"above": "cleanup"}
    assert operations[0]["request_body_template"]["layer"] == "layer"
    assert operations[0]["request_body_template"]["install-on"] == ["gateway"]
    assert all(isinstance(uid, str) for uid in operations[0]["request_body_template"]["source"])
    assert len(operations[1]["depends_on"]) == 1
    snapshot["responses"][-1]["data"]["rulebase"][0]["enabled"] = False
    changed = build_review(checkpoint_analysis, checkpoint_options, "source", **destination(snapshot, checkpoint_options))
    assert all(item.blockers for item in changed["plan"].items if item.family == "policy")
