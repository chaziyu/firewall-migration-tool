from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.model.policy import (
    CPAccessLayer,
    CPAccessRule,
    CPAccessSection,
    CPPolicyPackage,
)
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig


def test_traversal_follows_package_layers_and_inline_rules_without_reordering_source():
    root_a = CPAccessLayer(uid="root-a", name="Root A", package_uid="pkg")
    root_b = CPAccessLayer(uid="root-b", name="Root B", package_uid="pkg")
    inline = CPAccessLayer(uid="inline", name="Inline")
    package = CPPolicyPackage(uid="pkg", name="Package", access_layers=["root-a", "root-b"])
    section = CPAccessSection(uid="section", name="Section", layer_uid="root-a", section_path=["Section"])
    parent = CPAccessRule(
        uid="parent", name="Parent", layer_uid="root-a", order=6,
        section_path=["Section"], inline_layer="inline",
    )
    child = CPAccessRule(uid="child", name="Child", layer_uid="inline", order=4)
    later = CPAccessRule(uid="later", name="Later", layer_uid="root-a", order=2)
    other_layer = CPAccessRule(uid="other", name="Other", layer_uid="root-b", order=1)
    config = CheckPointConfig(
        policy_packages=[package], access_layers=[root_b, inline, root_a],
        access_sections=[section], access_rules=[parent, child, later, other_layer],
    )
    before = config.model_dump()

    result = build_checkpoint_derived_views(config).policy_traversal
    repeated = build_checkpoint_derived_views(config).policy_traversal

    assert [entry.rule_uid for entry in result.entries] == ["parent", "child", "later", "other"]
    assert [entry.traversal_position for entry in result.entries] == [1, 2, 3, 4]
    assert [entry.traversal_position for entry in repeated.entries] == [1, 2, 3, 4]
    assert [entry.rule_order for entry in result.entries] == [6, 4, 2, 1]
    assert result.entries[0].section_uid == "section"
    assert result.entries[1].source_rule is child
    assert (result.entries[1].layer_uid, result.entries[1].parent_layer_uid,
            result.entries[1].parent_rule_uid, result.entries[1].inline_depth) == (
                "inline", "root-a", "parent", 1,
            )
    assert all(entry.rule_uid != section.uid for entry in result.entries)
    assert config.model_dump() == before


def test_shared_inline_layer_is_reused_in_source():
    root = CPAccessLayer(uid="root", name="Root", package_uid="pkg")
    shared = CPAccessLayer(uid="shared", name="Shared")
    package = CPPolicyPackage(uid="pkg", name="Package", access_layers=["root"])
    parents = [
        CPAccessRule(uid="parent-1", layer_uid="root", inline_layer="shared"),
        CPAccessRule(uid="parent-2", layer_uid="root", inline_layer="shared"),
    ]
    child = CPAccessRule(uid="child", layer_uid="shared")
    config = CheckPointConfig(
        policy_packages=[package], access_layers=[root, shared], access_rules=[*parents, child],
    )
    before = config.model_dump()

    derived = build_checkpoint_derived_views(config)

    assert derived.references.by_uid["shared"] is shared
    assert sum(item is shared for item in config.access_layers) == 1
    assert sum(item is child for item in config.access_rules) == 1
    assert config.model_dump() == before


def test_inline_cycle_is_reported_and_traversal_stops_at_cycle():
    first = CPAccessLayer(uid="first", name="First", package_uid="pkg")
    second = CPAccessLayer(uid="second", name="Second")
    package = CPPolicyPackage(uid="pkg", name="Package", access_layers=["first"])
    rules = [
        CPAccessRule(uid="to-second", layer_uid="first", inline_layer="second"),
        CPAccessRule(uid="to-first", layer_uid="second", inline_layer="first"),
    ]

    result = build_checkpoint_derived_views(CheckPointConfig(
        policy_packages=[package], access_layers=[first, second], access_rules=rules,
    )).policy_traversal

    assert [entry.rule_uid for entry in result.entries] == ["to-second", "to-first"]
    assert len(result.issues) == 1
    assert result.issues[0].rule_uid == "to-first"


def test_unresolved_inline_layer_is_reported_on_parent_traversal_entry():
    root = CPAccessLayer(uid="root", name="Root", package_uid="pkg")
    package = CPPolicyPackage(uid="pkg", name="Package", access_layers=["root"])
    parent = CPAccessRule(uid="parent", layer_uid="root", inline_layer="missing-layer")

    derived = build_checkpoint_derived_views(CheckPointConfig(
        policy_packages=[package], access_layers=[root], access_rules=[parent],
    ))

    issue = derived.policy_traversal.entries[0].issues[0]
    assert issue.rule_uid == "parent"
    assert issue.reference == "missing-layer"
    assert issue.relationship_status == "missing"
    assert issue in derived.policy_traversal.issues
