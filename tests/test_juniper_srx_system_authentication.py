from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_authentication_order_and_server_dependencies_are_preserved():
    c = JuniperSRXParser("""
    set system authentication-order [ radius password ]
    set system radius-server r1 address 192.0.2.10
    set system tacplus-server t1 address 192.0.2.11
    """).parse_raw()
    assert c.authentication_order == ["radius", "password"]
    assert "r1" in c.radius_servers and "t1" in c.tacplus_servers
