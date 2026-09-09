from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_antivirus_profiles_are_structured_and_repeated_values_preserved():
    config = JuniperSRXParser(
        """
        set version 21.4R1.12
        set security utm feature-profile anti-virus profile av1 type kaspersky-lab-engine
        set security utm feature-profile anti-virus profile av1 scan-options scan-type http
        set security utm feature-profile anti-virus profile av1 scan-options scan-type ftp
        set security utm feature-profile anti-virus profile av1 fallback-options default-action log-and-permit
        set security utm feature-profile anti-virus profile av1 file-types [ exe zip ]
        set security utm feature-profile anti-virus profile av1 mime-types [ application/pdf text/plain ]
        """
    ).parse_raw()
    profile = config.contexts["root"].antivirus_profiles["av1"]
    assert profile.engine_type == "kaspersky-lab-engine"
    assert profile.scan_behavior["scan_type"] == ["http", "ftp"]
    assert profile.fallback_behavior["default_action"] == ["log-and-permit"]
    assert profile.file_controls == ["exe", "zip"]
    assert profile.mime_types == ["application/pdf", "text/plain"]


def test_antivirus_deactivated_child_is_not_effective_and_unknown_is_retained():
    config = JuniperSRXParser(
        """
        set security utm feature-profile anti-virus profile av1 type kaspersky-lab-engine
        deactivate security utm feature-profile anti-virus profile av1 type kaspersky-lab-engine
        set security utm feature-profile anti-virus profile av1 future-option enabled
        """
    ).parse_raw()
    profile = config.contexts["root"].antivirus_profiles["av1"]
    assert profile.engine_type is None
    assert profile.settings


def test_antivirus_profile_is_scoped_to_logical_system():
    config = JuniperSRXParser(
        "set logical-systems ls1 security utm feature-profile anti-virus profile av1 type engine"
    ).parse_raw()
    assert "av1" in config.contexts["ls1"].antivirus_profiles
