from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_ssl_ssh_certificate_deep_inspection_protocols_and_exemptions_are_typed():
    parsed = parse_fortigate_config('''config firewall ssl-ssh-profile
    edit "deep"
        set comment "Deep inspection"
        set inspection-mode deep-inspection
        config https
            set status enable
            set ports 443 8443
            set action inspect
        end
        config ssl-exempt
            edit "trusted"
                set address trusted-web
                set action bypass
            next
        end
        config certificate
            edit "inspection-ca"
                set certificate "ca-profile"
            next
        end
    next
end
''')
    profile = parsed.ssl_ssh_profiles[0]
    assert profile.inspection_mode == "deep-inspection"
    assert profile.protocols[0].ports == ["443", "8443"]
    assert profile.protocols[0].action == "inspect"
    assert profile.exemptions[0].address == "trusted-web"
    assert profile.exemptions[0].action == "bypass"
    assert profile.certificates[0].certificate == "ca-profile"
