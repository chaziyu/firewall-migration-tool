from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_idp_policy_rules_are_structured():
    c = JuniperSRXParser("""
    set security idp idp-policy p rulebase-ips rule r match signature sig1
    set security idp idp-policy p rulebase-ips rule r severity high
    set security idp idp-policy p rulebase-ips rule r action drop
    set security idp idp-policy p rulebase-ips rule r exception app1
    """).parse_raw().contexts["root"]
    r = c.idp_policies["p"].rulebase["rulebase-ips"][0]
    assert r.match["signature"] == ["sig1"] and r.action == "drop"
    assert r.severity == ["high"] and r.exceptions == ["app1"]
