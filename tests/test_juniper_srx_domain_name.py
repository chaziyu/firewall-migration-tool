from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_domain_name_is_structured():
    assert JuniperSRXParser("set system domain-name example.com").parse_raw().domain_name == "example.com"
