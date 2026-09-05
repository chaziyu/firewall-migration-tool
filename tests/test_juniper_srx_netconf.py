from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_netconf_ssh_transport_is_separate_from_generic_ssh():
    c = JuniperSRXParser("set system services netconf ssh rfc-compliant").parse_raw()
    assert c.netconf.enabled and not c.ssh.enabled
    assert "rfc-compliant" in c.netconf.options
