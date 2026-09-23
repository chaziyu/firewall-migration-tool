from fwmigrate.vendors.checkpoint.model.policy import CPAccessLayer, CPAccessRule, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.policy_structure import build_policy_structure


def test_policy_relationships_preserve_order_and_inline_parent():
    layer = CPAccessLayer(uid="l", name="layer", package_uid="p")
    inline = CPAccessLayer(uid="i", name="inline")
    package = CPPolicyPackage(uid="p", name="package", access_layers=["l"])
    rule = CPAccessRule(uid="r", name="rule", layer_uid="l", order=4, inline_layer="i")
    structure = build_policy_structure(CheckPointConfig(policy_packages=[package], access_layers=[layer, inline], access_rules=[rule]))
    assert structure.package_layers[0].layer is layer
    assert structure.rules[0].order == 4
    assert structure.inline_layers[0].inline_layer is inline and structure.inline_layers[0].parent_layer is layer

