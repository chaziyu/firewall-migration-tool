from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def test_https_inspection_is_separate_and_keeps_certificate_reference():
    result = extract_checkpoint_config("""{
      "responses": [{"command": "show-https-inspection-rulebase", "data": {"rulebase": [{
        "uid": "https-rule-1", "rule-number": 1, "name": "inspect-web",
        "source": ["any"], "destination": ["any"], "service": ["https"],
        "action": "Inspect", "certificate": "Corp-CA", "bypass": true,
        "comments": "bypass trusted site", "enabled": true, "install-on": ["gw-1"]
      }]}}]
    }""")

    assert result.canonical_ir.policies == []
    rule = result.canonical_ir.https_inspection_rules[0]
    assert rule.source_uuid == "https-rule-1"
    assert rule.rule_number == 1
    assert rule.certificate == "Corp-CA"
    assert rule.bypass is True
    assert rule.install_on == ["gw-1"]
