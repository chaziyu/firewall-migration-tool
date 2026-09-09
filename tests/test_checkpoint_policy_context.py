import json

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def _bundle(responses):
    return json.dumps({"format": "checkpoint-export-v1", "responses": responses})


def test_packages_are_domain_scoped_by_uid():
    result = extract_checkpoint_config(_bundle([
        {"command": "show-packages", "domain": "A", "data": {"objects": [
            {"uid": "package-a", "name": "Standard", "access-layers": [{"uid": "layer-a", "name": "Network"}]},
        ]}},
        {"command": "show-packages", "domain": "B", "data": {"objects": [
            {"uid": "package-b", "name": "Standard", "access-layers": [{"uid": "layer-b", "name": "Network"}]},
        ]}},
        {"command": "show-access-layers", "domain": "A", "data": {"objects": [
            {"uid": "layer-a", "name": "Network"},
        ]}},
        {"command": "show-access-layers", "domain": "B", "data": {"objects": [
            {"uid": "layer-b", "name": "Network"},
        ]}},
    ]))
    packages = result.canonical_ir.checkpoint_policy_packages
    assert {(p.domain_name, p.uid) for p in packages} == {("A", "package-a"), ("B", "package-b")}


def test_inline_layer_keeps_parent_and_child_context():
    result = extract_checkpoint_config(_bundle([
        {"command": "show-packages", "domain": "A", "data": {"objects": [
            {"uid": "package", "name": "Standard", "access-layers": [
                {"uid": "parent", "name": "Parent"}, {"uid": "child", "name": "Child"},
            ]},
        ]}},
        {"command": "show-access-layers", "domain": "A", "data": {"objects": [
            {"uid": "parent", "name": "Parent"}, {"uid": "child", "name": "Child"},
        ]}},
        {"command": "show-access-rulebase", "domain": "A", "package": "Standard",
         "package_uid": "package", "layer": "Parent", "layer_uid": "parent",
         "data": {"rulebase": [{"uid": "r10", "type": "access-rule", "rule-number": 10,
                                  "inline-layer": {"uid": "child", "name": "Child"}}]}},
        {"command": "show-access-rulebase", "domain": "A", "package": "Standard",
         "package_uid": "package", "layer": "Child", "layer_uid": "child",
         "parent_layer": "Parent", "parent_layer_uid": "parent", "parent_rule_uid": "r10",
         "data": {"rulebase": []}},
    ]))
    child = next(layer for layer in result.canonical_ir.checkpoint_access_layers if layer.uid == "child")
    assert child.inline is True
    assert child.parent_layer_uid == "parent"
    assert child.parent_rule_uid == "r10"
