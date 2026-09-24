from fwmigrate.vendors.checkpoint.model.policy import CPAccessLayer, CPAccessRule, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.policy_structure import build_policy_structure
from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.transform.policy import build_policy_traversal


def test_policy_relationships_preserve_order_and_inline_parent():
    layer = CPAccessLayer(uid="l", name="layer", package_uid="p")
    inline = CPAccessLayer(uid="i", name="inline")
    package = CPPolicyPackage(uid="p", name="package", access_layers=["l"])
    rule = CPAccessRule(uid="r", name="rule", layer_uid="l", order=4, inline_layer="i")
    structure = build_policy_structure(CheckPointConfig(policy_packages=[package], access_layers=[layer, inline], access_rules=[rule]))
    assert structure.package_layers[0].layer is layer
    assert structure.rules[0].order == 4
    assert structure.inline_layers[0].inline_layer is inline and structure.inline_layers[0].parent_layer is layer


def test_policy_traversal_emits_inline_children_after_parent():
    root = CPAccessLayer(uid="root", name="root", package_uid="p")
    inline = CPAccessLayer(uid="inline", name="inline")
    package = CPPolicyPackage(uid="p", name="package", access_layers=["root"])
    parent = CPAccessRule(uid="parent", name="parent", layer_uid="root", order=3, inline_layer="inline")
    child = CPAccessRule(uid="child", name="child", layer_uid="inline", order=1)

    result = build_policy_traversal(build_policy_structure(CheckPointConfig(
        policy_packages=[package], access_layers=[root, inline], access_rules=[parent, child],
    )))

    assert [entry.rule_uid for entry in result.entries] == ["parent", "child"]
    assert [entry.traversal_position for entry in result.entries] == [1, 2]
    assert [entry.rule_order for entry in result.entries] == [3, 1]
    assert (result.entries[1].inline_depth, result.entries[1].parent_rule_uid,
            result.entries[1].parent_layer_uid) == (1, "parent", "root")
    assert [entry.rule_uid for entry in build_checkpoint_derived_views(CheckPointConfig(
        policy_packages=[package], access_layers=[root, inline], access_rules=[parent, child],
    )).policy_traversal.entries] == ["parent", "child"]


def test_policy_traversal_reports_inline_layer_cycle_and_stops_path():
    first = CPAccessLayer(uid="first", name="first", package_uid="p")
    second = CPAccessLayer(uid="second", name="second")
    package = CPPolicyPackage(uid="p", name="package", access_layers=["first"])
    rules = [
        CPAccessRule(uid="to-second", layer_uid="first", inline_layer="second"),
        CPAccessRule(uid="to-first", layer_uid="second", inline_layer="first"),
    ]

    result = build_policy_traversal(build_policy_structure(CheckPointConfig(
        policy_packages=[package], access_layers=[first, second], access_rules=rules,
    )))

    assert [entry.rule_uid for entry in result.entries] == ["to-second", "to-first"]
    assert len(result.issues) == 1
    assert result.issues[0].rule_uid == "to-first"
    assert result.entries[-1].issues == result.issues
