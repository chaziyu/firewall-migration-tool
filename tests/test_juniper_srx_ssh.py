from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_ssh_enablement_and_options_are_separate_from_user_keys():
    c = JuniperSRXParser("set system services ssh root-login deny").parse_raw()
    assert c.ssh.enabled
    assert "root-login_deny" in c.ssh.options
