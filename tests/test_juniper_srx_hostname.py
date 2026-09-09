from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_deactivated_hostname_child_is_not_effective():
    config = JuniperSRXParser("set system host-name fw\ndeactivate system host-name\nset system host-name inactive").parse_raw()
    assert config.hostname is None
