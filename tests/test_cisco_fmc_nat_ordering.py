import json

from fwmigrate.parsers.cisco_ftd import CiscoFMCBundleParser


def _bundle(indices):
    rules = []
    for position, target_index in enumerate(indices, 1):
        rules.append({
            "id": f"rule-{position}",
            "name": f"Rule {position}",
            "natType": "STATIC",
            "targetIndex": target_index,
            "ruleIndex": target_index,
            "originalSource": {"id": "inside"},
            "translatedSource": {"id": "public"},
        })
    return {
        "format": "cisco-fmc-rest-export-v1",
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {
            "hosts": [
                {"id": "inside", "name": "Inside", "type": "Host", "value": "10.0.0.10"},
                {"id": "public", "name": "Public", "type": "Host", "value": "203.0.113.10"},
            ],
        },
        "nat_policies": [{
            "id": "nat-policy",
            "name": "NAT Policy",
            "manual_rules_before_auto": rules,
            "auto_rules": [],
            "manual_rules_after_auto": [],
        }],
    }


def test_fmc_nat_order_metadata_matching_bundle_order_is_preserved():
    ir = CiscoFMCBundleParser(json.dumps(_bundle([10, 20]))).parse()

    assert [rule.sequence for rule in ir.nat_rules] == [1, 2]
    assert [rule.source_attributes["fmc_bundle_position"] for rule in ir.nat_rules] == [1, 2]
    assert all(rule.source_attributes["fmc_order_consistent"] is True for rule in ir.nat_rules)
    assert all("fmc_order_review_reason" not in rule.source_attributes for rule in ir.nat_rules)


def test_fmc_nat_order_metadata_conflict_fails_closed_without_reordering():
    ir = CiscoFMCBundleParser(json.dumps(_bundle([20, 10]))).parse()

    assert [rule.name for rule in ir.nat_rules] == ["NAT Policy__Rule 1", "NAT Policy__Rule 2"]
    assert [rule.sequence for rule in ir.nat_rules] == [1, 2]
    assert all(rule.source_attributes["fmc_order_consistent"] is False for rule in ir.nat_rules)
    assert all(rule.requires_manual_review is True for rule in ir.nat_rules)
    assert all(rule.migration_status == "PARTIALLY_NORMALIZED" for rule in ir.nat_rules)
    assert all(
        "ordering metadata conflicts" in rule.source_attributes["fmc_order_review_reason"]
        for rule in ir.nat_rules
    )
    assert ir.generation_safe is False
    assert "FMC policy/NAT semantics require manual target validation" in ir.generation_blocking_reasons


def test_fmc_nat_duplicate_order_metadata_fails_closed():
    ir = CiscoFMCBundleParser(json.dumps(_bundle([10, 10]))).parse()

    assert all(rule.source_attributes["fmc_order_consistent"] is False for rule in ir.nat_rules)
    assert all(rule.requires_manual_review is True for rule in ir.nat_rules)
