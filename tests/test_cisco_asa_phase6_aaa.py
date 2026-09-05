from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def parse(text: str):
    return CiscoASAParser(text).parse_raw()


def test_aaa_server_hierarchy_is_structured_and_redacted():
    secret = "SYNTHETIC_AAA_SECRET"
    config = parse(f"""
interface GigabitEthernet0/1
 nameif inside
aaa-server RAD protocol radius
aaa-server RAD (inside) host 10.0.0.1
 key {secret}
 authentication-port 1812
 accounting-port 1813
 timeout 5
""")
    group = config.aaa_server_groups[0]
    host = config.aaa_server_hosts[0]
    assert (group.name, group.protocol, group.hosts) == ("RAD", "radius", ["10.0.0.1"])
    assert (host.group_name, host.interface, host.authentication_port, host.accounting_port) == ("RAD", "inside", 1812, 1813)
    assert host.key_present and secret not in repr(config.model_dump())
    assert not any(issue["reference_type"] == "interface" and not issue["resolved"] for issue in config.reference_issues)


def test_aaa_rules_preserve_local_fallback_and_missing_group_review():
    config = parse("""
aaa-server RAD protocol radius
aaa authentication ssh inside RAD LOCAL
aaa authorization command MISSING
aaa accounting ssh inside RAD
""")
    assert config.aaa_authentication_rules[0].fallback_local is True
    assert config.aaa_authentication_rules[0].server_group == "RAD"
    missing = config.aaa_authorization_rules[0]
    assert missing.migration_status == "PARTIALLY_NORMALIZED"
    assert any(issue["reference_name"] == "MISSING" and not issue["resolved"] for issue in config.reference_issues)


def test_local_user_secret_is_presence_only():
    secret = "SYNTHETIC_LOCAL_SECRET"
    config = parse(f"username admin privilege 15 secret {secret}")
    user = config.local_users[0]
    assert (user.username, user.privilege, user.secret_present) == ("admin", 15, True)
    assert secret not in repr(config.model_dump())


def test_unknown_and_malformed_aaa_options_are_visible():
    config = parse("""
aaa-server UNKNOWN protocol kerberos
aaa-server UNKNOWN (inside) host 10.0.0.2
 mystery-option value
aaa-server UNKNOWN (inside) host 10.0.0.3
 authentication-port bad
""")
    assert config.aaa_server_groups[0].protocol == "kerberos"
    assert config.aaa_server_hosts[0].migration_status == "PARTIALLY_NORMALIZED"
    assert config.aaa_server_hosts[1].migration_status == "PARSE_ERROR"
