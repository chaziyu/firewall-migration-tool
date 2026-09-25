from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.model.policy import CPAccessRule, CPAccessSection


def test_rulebase_keeps_package_layer_and_rule_order():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "r81_golden_matrix.json").read_text()
    config = extract_checkpoint_source(source).config
    assert config.access_rules
    assert all(type(item) is CPAccessRule for item in config.access_rules)
    assert all(type(item) is CPAccessSection for item in config.access_sections)
    orders = [item.order for item in config.access_rules if item.order is not None]
    assert orders and orders[0] == 1 and set(orders) >= {1, 2, 3, 4}
