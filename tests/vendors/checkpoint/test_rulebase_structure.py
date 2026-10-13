import json
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


def test_package_scoped_rulebases_keep_package_ownership():
    source = json.dumps({"responses": [
        {"command": "show-nat-rulebase", "domain": "D", "package": "P1", "package_uid": "p1",
         "data": {"rulebase": [{"uid": "n1", "type": "nat-rule", "rule-number": 1,
                                "original-source": "Any", "original-destination": "Any", "original-service": "Any"}]}},
        {"command": "show-nat-rulebase", "domain": "D", "package": "P2", "package_uid": "p2",
         "data": {"rulebase": [{"uid": "n2", "type": "nat-rule", "rule-number": 1,
                                "original-source": "Any", "original-destination": "Any", "original-service": "Any"}]}},
    ]})
    result = extract_checkpoint_source(source)

    assert [(rule.package, rule.package_uid, rule.order) for rule in result.config.nat_rules] == [
        ("P1", "p1", 1), ("P2", "p2", 1),
    ]
    assert not any(issue.code == "nat_order_malformed" for issue in result.validation.issues)
