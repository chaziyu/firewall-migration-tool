from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_web_filtering_preserves_categories_lists_actions_and_logging_independently():
    config = JuniperSRXParser(
        """
        set security utm feature-profile web-filtering profile web1 url-categories [ adult gambling ]
        set security utm feature-profile web-filtering profile web1 custom-url-list deny-list
        set security utm feature-profile web-filtering profile web1 action block
        set security utm feature-profile web-filtering profile web1 logging session-init
        """
    ).parse_raw()
    profile = config.contexts["root"].web_filtering_profiles["web1"]
    assert profile.url_categories == ["adult", "gambling"]
    assert profile.custom_url_lists == ["deny-list"]
    assert profile.actions == ["block"]
    assert profile.logging == ["session-init"]
