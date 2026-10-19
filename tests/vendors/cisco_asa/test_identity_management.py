from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser
import pytest

from types import SimpleNamespace





from fwmigrate.vendors.cisco_asa.relationships.identity import build_identity_relationships



from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceIndex


@pytest.mark.parametrize(("commands", "enabled"), [
    ("no http server enable", False),
    ("http server enable\nno http server enable", False),
    ("no http server enable\nhttp server enable", True),
    ("http server idle-timeout 10\nno http server idle-timeout", None),
    ("http server session-timeout 20\nno http server session-timeout", None),
])
def test_http_negation_preserves_explicit_state_and_evidence(commands, enabled):
    config = CiscoASAParser(commands).parse_raw()
    assert config.http_server.enabled is enabled
    assert config.http_server.idle_timeout is None
    assert config.http_server.session_timeout is None
    assert config.http_server.raw_lines == commands.splitlines()
    assert not config.parse_errors


def test_absent_http_and_invalid_port_are_not_defaults():
    assert CiscoASAParser("hostname asa").parse_raw().http_server is None
    config = CiscoASAParser("http server enable 70000").parse_raw()
    assert config.http_server.port is None
    assert config.parse_errors



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

def test_unmatched_identity_selector_is_source_selector_not_missing_local_user():
    rule = SimpleNamespace(name="auth", source_context="ctx", group_name=None, server_group=None,
                           interface=None, acl_reference=None, user_identity="remote-user")
    config = SimpleNamespace(aaa_server_hosts=[], aaa_authentication_rules=[rule],
                             aaa_authorization_rules=[], aaa_accounting_rules=[])

    relation = build_identity_relationships(config, ASAReferenceIndex()).relationships[0]

    assert relation.local_user is None and relation.user_group is None
    assert relation.selector_status == "SOURCE_SELECTOR"
    assert not build_identity_relationships(config, ASAReferenceIndex()).issues
