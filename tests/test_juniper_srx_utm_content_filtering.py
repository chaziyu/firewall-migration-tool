from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_content_filtering_preserves_version_sensitive_known_options():
    config = JuniperSRXParser(
        """
        set version 21.4R1.12
        set security utm feature-profile content-filtering profile cf1 content-types [ exe pdf ]
        set security utm feature-profile content-filtering profile cf1 action block
        set security utm feature-profile content-filtering profile cf1 future-child enabled
        """
    ).parse_raw()
    profile = config.contexts["root"].content_filtering_profiles["cf1"]
    assert profile.content_types == ["exe", "pdf"]
    assert profile.actions == ["block"]
    assert profile.syntax_variant == "future-child"
    assert profile.settings
