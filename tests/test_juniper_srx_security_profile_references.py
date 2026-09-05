from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_policy_application_services_are_typed():
    c = JuniperSRXParser("set security policies from-zone a to-zone b policy p then permit application-services ssl1").parse_raw()
    assert c.contexts["root"].policies[0].application_services == ["ssl1"]
