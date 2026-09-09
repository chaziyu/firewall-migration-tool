from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_security_intelligence_feeds_and_actions_stay_distinct():
    c = JuniperSRXParser("""
    set security intelligence feed f url https://feed.example/a
    set security intelligence profile p feed f
    set security intelligence profile p action log
    """).parse_raw().contexts["root"]
    assert c.security_intelligence_feeds["f"].references == ["https://feed.example/a"]
    assert c.security_intelligence_profiles["p"].feeds == ["f"]
    assert c.security_intelligence_profiles["p"].actions == ["log"]
