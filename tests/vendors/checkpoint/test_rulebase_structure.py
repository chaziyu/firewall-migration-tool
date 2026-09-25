from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.model.policy import CPAccessRule, CPAccessSection
from fwmigrate.vendors.checkpoint.model.policy import CPAccessLayer, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.validation import validate_checkpoint_config


def test_rulebase_keeps_package_layer_and_rule_order():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "r81_golden_matrix.json").read_text()
    config = extract_checkpoint_source(source).config
    assert config.access_rules
    assert all(type(item) is CPAccessRule for item in config.access_rules)
    assert all(type(item) is CPAccessSection for item in config.access_sections)
    orders = [item.order for item in config.access_rules if item.order is not None]
    assert orders and orders[0] == 1 and set(orders) >= {1, 2, 3, 4}


def test_shared_inline_layer_is_related_to_each_rule_but_not_as_package_root():
    root = CPAccessLayer(uid="root", name="Root")
    child = CPAccessLayer(uid="child", name="Inline", parent_rule_uid="collector-context")
    config = CheckPointConfig(
        policy_packages=[CPPolicyPackage(uid="p1", access_layers=["root"]),
                         CPPolicyPackage(uid="p2", access_layers=["root"])],
        access_layers=[root, child],
        access_rules=[CPAccessRule(uid="r1", layer_uid="root", inline_layer="child"),
                      CPAccessRule(uid="r2", layer_uid="root", inline_layer="child")],
    )
    derived = build_checkpoint_derived_views(config)

    assert len(derived.policy_structure.package_layers) == 2
    assert all(item.layer is root for item in derived.policy_structure.package_layers)
    assert len(derived.policy_structure.inline_layers) == 2
    assert all(item.inline_layer is child for item in derived.policy_structure.inline_layers)
    assert child not in [item.layer for item in derived.policy_structure.package_layers]
    assert not {item.code for item in validate_checkpoint_config(config, derived).issues}
    assert child.parent_rule_uid == "collector-context"
