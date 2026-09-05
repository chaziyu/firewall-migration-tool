from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_dns_name_servers_domain_and_search_are_structured():
    c = JuniperSRXParser("""
    set system name-server 2001:db8::53 routing-instance mgmt
    set system domain-name example.com
    set system domain-search [ corp.example example.com ]
    """).parse_raw()
    assert c.name_servers[0].routing_instance == "mgmt"
    assert c.domain_search == ["corp.example", "example.com"]
