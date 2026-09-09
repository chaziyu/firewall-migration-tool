import json

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def test_threat_prevention_is_separate_and_ordered():
    result = extract_checkpoint_config(json.dumps({"responses": [
        {"command": "show-threat-profiles", "data": {"objects": [{"uid": "p1", "name": "IPS", "family": "IPS", "exceptions": [{"id": 1}]}]}},
        {"command": "show-threat-rulebase", "package": "P", "layer": "TP", "data": {"rulebase": [{"uid": "t1", "rule-number": 1, "name": "first", "source": ["Any"], "profile": {"name": "IPS"}, "action": "Prevent", "enabled": True}, {"uid": "t2", "rule-number": 2, "name": "second", "profile": "IPS", "enabled": False}]}},
    ]}))
    assert [rule.name for rule in result.canonical_ir.checkpoint_threat_prevention_rules] == ["first", "second"]
    assert result.canonical_ir.checkpoint_threat_prevention_profiles[0].family == "IPS"
    assert not result.canonical_ir.policies
