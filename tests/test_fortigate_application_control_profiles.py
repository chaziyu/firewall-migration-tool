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
