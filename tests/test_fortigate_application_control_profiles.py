from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_application_ids_filters_risk_and_overrides_are_typed():
    parsed = parse_fortigate_config('''config application list
    edit "apps"
        config entries
            edit 1
                set application 12345
                set category collaboration
                set risk high
                set action block
            next
        end
        config filters
            edit "risky"
                set category unknown
                set risk critical
            next
        end
        config overrides
            edit "approved"
                set application 12345
                set action allow
            next
        end
    next
end
''')
    profile = parsed.application_lists[0]
    assert profile.entries[0].application_id == 12345
    assert profile.entries[0].risk == "high"
    assert profile.entries[0].action == "block"
    assert profile.filters[0].risk == "critical"
    assert profile.overrides[0].application == "12345"
    assert profile.overrides[0].action == "allow"


def test_application_entries_support_multiple_categories_and_applications():
    parsed = parse_fortigate_config('''config application list
    edit "block-high-risk"
        set unknown-application-log enable
        config entries
            edit 1
                set category 2 6 7
            next
            edit 2
                set application 11414 11767 15722
                set action pass
            next
        end
    next
end
''')
    profile = parsed.application_lists[0]
    assert profile.name == "block-high-risk"
    assert len(profile.entries) == 2
    assert profile.entries[0].category == ["2", "6", "7"]
    assert profile.entries[1].application == ["11414", "11767", "15722"]
    assert profile.entries[1].action == "pass"


def test_application_fixture_parses_successfully():
    from pathlib import Path
    fixture_path = Path(__file__).parent / "fixtures" / "fortigate" / "application_list_multiple_categories.conf"
    content = fixture_path.read_text(encoding="utf-8")
    parsed = parse_fortigate_config(content)
    profile = parsed.application_lists[0]
    assert profile.name == "block-high-risk"
    assert profile.entries[0].category == ["2", "6", "7"]
    assert profile.entries[1].action == "pass"


