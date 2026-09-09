from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_antispam_profile_keeps_servers_actions_and_sanitizes_secrets():
    config = JuniperSRXParser(
        """
        set security utm feature-profile anti-spam profile as1 server 192.0.2.10
        set security utm feature-profile anti-spam profile as1 action reject
        set security utm feature-profile anti-spam profile as1 authentication-key ascii-text super-secret
        """
    ).parse_raw()
    profile = config.contexts["root"].anti_spam_profiles["as1"]
    assert profile.servers == ["192.0.2.10"]
    assert profile.actions == ["reject"]
    assert "super-secret" not in config.model_dump_json()
    assert profile.settings
