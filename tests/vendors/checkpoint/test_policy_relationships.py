from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.model.policy import CPAccessLayer, CPAccessRule, CPAccessSection, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.policy_structure import build_policy_structure
from fwmigrate.vendors.checkpoint.policy_context import CPPolicyContextRecord


def test_policy_relationships_preserve_order_and_inline_parent():
    layer = CPAccessLayer(uid="l", name="layer", package_uid="p")
    inline = CPAccessLayer(uid="i", name="inline")
    package = CPPolicyPackage(uid="p", name="package", access_layers=["l"])
    rule = CPAccessRule(uid="r", name="rule", layer_uid="l", order=4, inline_layer="i")
    structure = build_policy_structure(CheckPointConfig(policy_packages=[package], access_layers=[layer, inline], access_rules=[rule]))
    assert structure.package_layers[0].layer is layer
    assert structure.rules[0].order == 4
    assert structure.inline_layers[0].inline_layer is inline and structure.inline_layers[0].parent_layer is layer


def test_policy_relationships_are_domain_scoped_and_orphans_remain_visible():
    layer_a = CPAccessLayer(uid="la", name="Shared", domain_uid="d1")
    layer_b = CPAccessLayer(uid="lb", name="Shared", domain_uid="d2")
    section = CPAccessSection(uid="s", name="Section", domain_uid="d2", layer="Shared")
    orphan = CPAccessRule(
        uid="r", name="orphan", domain_uid="d2", package="Package B", package_uid="p2",
        layer="Missing", layer_uid="missing-layer", order=1,
    )
    config = CheckPointConfig(access_layers=[layer_a, layer_b], access_sections=[section], access_rules=[orphan])

    derived = build_checkpoint_derived_views(config, policy_context=(CPPolicyContextRecord(section, ("Section",)),))

    assert derived.policy_structure.sections[0].layer is layer_b
    assert derived.policy_structure.sections[0].section_path == ("Section",)
    assert len(derived.policy_traversal.entries) == 1
    entry = derived.policy_traversal.entries[0]
    assert entry.source_rule is orphan
    assert (entry.package_name, entry.layer_uid, entry.rule_order) == ("Package B", "missing-layer", 1)
    assert entry.issues[0].relationship_status == "unresolved_owner"
