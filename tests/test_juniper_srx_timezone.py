from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_deactivated_timezone_child_is_not_effective():
    c = JuniperSRXParser("set system time-zone UTC\ndeactivate system time-zone\nset system time-zone Asia/Kuala_Lumpur").parse_raw()
    assert c.time_zone is None
