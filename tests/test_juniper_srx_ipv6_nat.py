from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_nptv6_is_not_source_nat():
    c = JuniperSRXParser("set security nat nptv6 prefix 2001:db8::/48").parse_raw().contexts["root"]
    assert c.nat.source_attributes["ipv6"][0]["nat_family"] == "nptv6"
    assert not c.nat.source_rule_sets
