from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def test_command_privileges_and_local_fallback_are_source_records():
    config = CiscoASAParser("""aaa authorization command AUTH LOCAL
username operator privilege 7 nopassword
privilege cmd level 7 mode exec command show version
privilege show level 5 command running-config
""").parse_raw()
    assert config.aaa_authorization_rules[0].fallback_local is True
    assert config.local_users[0].privilege == 7
    assert "privilege" in config.local_users[0].explicit_fields
    assert [(p.command_form, p.privilege_level, p.cli_mode) for p in config.command_privileges] == [("cmd", 7, "exec"), ("show", 5, None)]
