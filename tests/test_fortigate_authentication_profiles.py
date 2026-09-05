from pathlib import Path

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_authentication_lists_and_dual_stack_selectors_stay_ordered():
    config = '''
config authentication scheme
    edit "scheme"
        set method basic certificate
        set user-database "ldap" "radius"
    next
end
config authentication rule
    edit "rule"
        set srcintf "wan1"
        set srcaddr "v4-src"
        set srcaddr6 "v6-src"
        set dstaddr "v4-dst"
        set dstaddr6 "v6-dst"
        set protocol http https
        set status enable
        set active-auth-method "scheme"
    next
end
'''
    parsed = parse_fortigate_config(config)
    scheme = parsed.authentication_schemes[0]
    rule = parsed.authentication_rules[0]
    assert scheme.method == ["basic", "certificate"]
    assert scheme.user_database == ["ldap", "radius"]
    assert rule.srcaddr6 == ["v6-src"]
    assert rule.dstaddr == ["v4-dst"]
    assert rule.dstaddr6 == ["v6-dst"]
    assert rule.protocol == ["http", "https"]


def test_security_profiles_have_typed_nested_sections_and_source_fallback():
    config = Path("tests/fixtures/fortigate/security_profiles_full.conf").read_text()
    parsed = parse_fortigate_config(config)
    assert parsed.antivirus_profiles[0].name == "av"
    assert parsed.webfilter_profiles[0].name == "web"
    assert parsed.dnsfilter_profiles[0].name == "dns"
    assert parsed.application_lists[0].name == "apps"
    assert parsed.ssl_ssh_profiles[0].name == "ssl"
    assert any(item.source_path == "antivirus profile" for item in parsed.structured_source_objects)
