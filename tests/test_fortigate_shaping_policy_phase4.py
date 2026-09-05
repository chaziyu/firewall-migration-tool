from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_shaping_policy_typed_selectors_and_shapers():
    config = """
config firewall shaping-policy
    edit 7
        set srcintf "lan" "guest"
        set dstintf "wan1" "wan2"
        set srcaddr "inside" "guest-net"
        set dstaddr "internet"
        set srcaddr6 "inside-v6"
        set dstaddr6 "internet-v6"
        set srcaddr-negate enable
        set dstaddr6-negate disable
        set service "HTTPS" "DNS"
        set schedule "business-hours"
        set traffic-shaper "gold"
        set traffic-shaper-reverse "silver"
        set per-ip-shaper "client-limit"
        set per-ip-shaper-reverse "client-limit-reverse"
        set application "Web.Client" "DNS"
        set app-category 10 20
        set app-group "web-apps"
        set url-category "approved"
        set status disable
        set comments "shape reviewed traffic"
    next
end
"""
    fg = parse_fortigate_config(config)
    policy = fg.shaping_policies[0]

    assert policy.srcintf == ["lan", "guest"]
    assert policy.dstintf == ["wan1", "wan2"]
    assert policy.srcaddr6 == ["inside-v6"]
    assert policy.dstaddr6 == ["internet-v6"]
    assert policy.srcaddr_negate == "enable"
    assert policy.dstaddr6_negate == "disable"
    assert policy.service == ["HTTPS", "DNS"]
    assert policy.schedule == "business-hours"
    assert policy.per_ip_shaper_reverse == "client-limit-reverse"
    assert policy.application == ["Web.Client", "DNS"]
    assert policy.app_category == ["10", "20"]
    assert policy.app_group == ["web-apps"]
    assert policy.url_category == ["approved"]
    assert policy.status == "disable"
    assert policy.comments == "shape reviewed traffic"
    assert not policy.extra_settings

    result = extract_fortigate_config(config)
    section = next(s for s in result.source_sections if s.path == "firewall shaping-policy")
    assert section.status == ExtractionStatus.NORMALIZED
