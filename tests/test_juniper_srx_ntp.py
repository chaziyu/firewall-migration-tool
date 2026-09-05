from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_ntp_servers_peers_preference_context_and_key_reference():
    c = JuniperSRXParser("""
    set system ntp server 2001:db8::123 prefer routing-instance mgmt
    set system ntp peer ntp.example authentication-key 7
    set system ntp source-address 2001:db8::10
    set system ntp authentication-key 7 type md5 secret-value
    """).parse_raw()
    assert c.ntp.servers[0].preferred and c.ntp.servers[0].routing_instance == "mgmt"
    assert c.ntp.servers[1].authentication_key_reference == "7"
    assert c.ntp.source_address == "2001:db8::10"
    assert "secret-value" not in c.model_dump_json()
