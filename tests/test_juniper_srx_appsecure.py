from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_appsecure_rule_sets_and_rules_keep_source_order():
    config = JuniperSRXParser(
        """
        set services application-identification rule-set rs rule first match application web
        set services application-identification rule-set rs rule second match application ssh
        set services application-identification rule-set rs future-child enabled
        """
    ).parse_raw()
    ruleset = config.contexts["root"].appsecure_rule_sets["rs"]
    assert [rule.name for rule in ruleset.rules] == ["first", "second"]
    assert ruleset.settings
