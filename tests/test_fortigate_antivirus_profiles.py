from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_antivirus_protocol_scanning_and_actions_are_typed():
    parsed = parse_fortigate_config('''
config antivirus profile
    edit "strict-av"
        set comment "Strict scanning"
        set inspection-mode proxy
        config http
            set av-scan block
            set outbreak-prevention enable
            config archive-content
                edit "zip"
                    set action block
                next
            end
        end
        config ftp
            set av-scan monitor
        end
    next
end
''')
    profile = parsed.antivirus_profiles[0]
    assert profile.comment == "Strict scanning"
    assert profile.inspection_mode == "proxy"
    assert [item.name for item in profile.protocols] == ["http", "ftp"]
    assert profile.protocols[0].settings["av_scan"] == "block"
    assert profile.protocols[0].settings["outbreak_prevention"] == "enable"
    assert profile.protocols[0].configs[0].name == "zip"
    assert profile.protocols[0].configs[0].action == "block"
    assert profile.protocols[1].settings["av_scan"] == "monitor"
