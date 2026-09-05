from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_ipv6_any_policy_reference_is_not_rewritten():
    p = JuniperSRXParser("set security policies from-zone a to-zone b policy p match source-address any-ipv6").parse_raw().contexts["root"].policies[0]
    assert p.source_addresses == ["any-ipv6"]
