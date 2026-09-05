from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_nat_pool_and_match_member_history():
    cfg = JuniperSRXParser("""
set groups G1 security nat source pool p address 203.0.113.10/32
set groups G1 security nat source rule-set rs rule r match source-address 10.0.0.0/8
set groups G1 security nat source rule-set rs rule r then source-nat pool p
set apply-groups G1
set security nat source pool p address 203.0.113.10/32
set security nat source rule-set rs rule r match source-address 10.0.0.0/8
set security nat source rule-set rs rule r then source-nat interface
""").parse_raw()
    context = cfg.contexts["root"]
    rule = context.nat.source_rule_sets["rs"].rules[0]
    assert rule.action["type"] == "interface"
    assert len(rule.match.member_candidate_history["source_addresses"]) == 2
    assert rule.field_candidate_history["action"][0].shadowed
