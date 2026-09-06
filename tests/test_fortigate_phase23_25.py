from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def _by_name(items):
    return {item.name: item for item in items}


def test_phase23_shaping_policy_keeps_order_lists_and_shaper_references_separate() -> None:
    content = """
config firewall shaping-policy
    edit 10
        set name "apps-first"
        set status enable
        set srcintf "lan" "dmz"
        set dstintf "wan1"
        set srcaddr "src-a" "src-b"
        append srcaddr "src-c"
        set dstaddr "dst-a" "dst-b"
        set srcaddr6 "src6-a"
        set dstaddr6 "dst6-a" "dst6-b"
        set service "HTTP" "HTTPS"
        set traffic-shaper "forward-shaper"
        set traffic-shaper-reverse "reverse-shaper"
        set per-ip-shaper "per-user"
        set per-ip-shaper-reverse "per-user-reverse"
        set application 101 bad-id 202
        set app-category 5 6
        set app-group "business" "collaboration"
        set url-category 3 4
        set comment "phase 23 shaping rule"
    next
    edit 20
        set name "second-rule"
        set dstintf "wan2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set traffic-shaper "second-forward"
    next
end
"""

    parsed = parse_fortigate_config(content)
    assert [policy.id for policy in parsed.shaping_policies] == [10, 20]

    policy = parsed.shaping_policies[0]
    assert policy.status == "enable"
    assert policy.srcintf == ["lan", "dmz"]
    assert policy.dstintf == ["wan1"]
    assert policy.srcaddr == ["src-a", "src-b", "src-c"]
    assert policy.dstaddr == ["dst-a", "dst-b"]
    assert policy.srcaddr6 == ["src6-a"]
    assert policy.dstaddr6 == ["dst6-a", "dst6-b"]
    assert policy.service == ["HTTP", "HTTPS"]
    assert policy.application == [101, 202]
    assert policy.app_category == [5, 6]
    assert policy.app_group == ["business", "collaboration"]
    assert policy.url_category == ["3", "4"]
    assert policy.traffic_shaper == "forward-shaper"
    assert policy.traffic_shaper_reverse == "reverse-shaper"
    assert policy.per_ip_shaper == "per-user"
    assert policy.per_ip_shaper_reverse == "per-user-reverse"
    assert policy.comment == "phase 23 shaping rule"
    assert policy.extra_settings["unparsed_application"] == ["bad-id"]
    assert "comment" not in policy.extra_settings

    result = extract_fortigate_config(content)
    section = next(
        item for item in result.source_sections
        if item.path == "firewall shaping-policy"
    )
    assert section.status == ExtractionStatus.EXTRACT_ONLY
    assert section.object_count_source == 2
    assert section.object_count_parsed == 2


def test_phase24_address_types_remain_type_specific_and_malformed_color_is_retained() -> None:
    content = """
config firewall address
    edit "subnet"
        set type ipmask
        set subnet 10.0.0.0 255.255.255.0
        set associated-interface "port2"
        set color 7
    next
    edit "range"
        set type iprange
        set start-ip 10.0.1.10
        set end-ip 10.0.1.20
    next
    edit "wildcard"
        set type wildcard
        set wildcard 10.10.0.0 0.0.255.255
    next
    edit "fqdn"
        set type fqdn
        set fqdn "api.example.com"
        set wildcard-fqdn "*.legacy.example.com"
    next
    edit "geo"
        set type geography
        set country MY
    next
    edit "dynamic"
        set type dynamic
        set sub-type ems-tag
        set obj-tag "managed-endpoints"
        set filter "tag == managed"
        set sdn "ems-connector"
    next
    edit "interface-subnet"
        set type interface-subnet
        set interface "port3"
    next
    edit "route-tag"
        set type route-tag
        set route-tag 4096
    next
    edit "mac"
        set type mac
        set macaddr "00:11:22:33:44:55-00:11:22:33:44:66"
    next
    edit "bad-color"
        set type fqdn
        set fqdn "bad-color.example.com"
        set color not-a-number
    next
end
config firewall address6
    edit "ipv6-network"
        set ip6 2001:db8:1::/64
    next
    edit "ipv6-range"
        set type iprange
        set start-ip 2001:db8:2::10
        set end-ip 2001:db8:2::20
    next
end
config firewall wildcard-fqdn custom
    edit "wildcard-custom"
        set wildcard-fqdn "*.cdn.example.com"
    next
end
"""

    parsed = parse_fortigate_config(content)
    addresses = _by_name(parsed.addresses)

    assert addresses["subnet"].type == "ipmask"
    assert addresses["subnet"].subnet == "10.0.0.0 255.255.255.0"
    assert addresses["subnet"].associated_interface == "port2"
    assert addresses["subnet"].color == 7

    assert addresses["range"].type == "iprange"
    assert addresses["range"].start_ip == "10.0.1.10"
    assert addresses["range"].end_ip == "10.0.1.20"

    assert addresses["wildcard"].type == "wildcard"
    assert addresses["wildcard"].wildcard == "10.10.0.0 0.0.255.255"

    assert addresses["fqdn"].type == "fqdn"
    assert addresses["fqdn"].fqdn == "api.example.com"
    assert addresses["fqdn"].wildcard_fqdn == "*.legacy.example.com"

    assert addresses["geo"].type == "geography"
    assert addresses["geo"].country == "MY"

    dynamic = addresses["dynamic"]
    assert dynamic.type == "dynamic"
    assert dynamic.sub_type == "ems-tag"
    assert dynamic.obj_tag == "managed-endpoints"
    assert dynamic.filter == "tag == managed"
    assert dynamic.sdn == "ems-connector"

    interface_subnet = addresses["interface-subnet"]
    assert interface_subnet.type == "interface-subnet"
    assert interface_subnet.interface == "port3"
    assert interface_subnet.associated_interface is None

    assert addresses["route-tag"].type == "route-tag"
    assert addresses["route-tag"].route_tag == 4096
    assert addresses["mac"].type == "mac"
    assert addresses["mac"].macaddr == "00:11:22:33:44:55-00:11:22:33:44:66"

    assert addresses["bad-color"].color is None
    assert addresses["bad-color"].extra_settings["unparsed_color"] == "not-a-number"

    ipv6 = [item for item in parsed.addresses if item.is_ipv6]
    ipv6_by_name = _by_name(ipv6)
    assert ipv6_by_name["ipv6-network"].ip6 == "2001:db8:1::/64"
    assert ipv6_by_name["ipv6-range"].type == "iprange"
    assert ipv6_by_name["ipv6-range"].start_ip == "2001:db8:2::10"
    assert ipv6_by_name["ipv6-range"].end_ip == "2001:db8:2::20"

    wildcard = _by_name(parsed.wildcard_fqdns)["wildcard-custom"]
    assert wildcard.wildcard_fqdn == "*.cdn.example.com"


def test_phase25_address_group_preserves_member_mutation_exclusions_dynamic_filter_and_tags() -> None:
    content = """
config firewall addrgrp
    edit "ordered-static"
        set member "old-a" "old-b"
        append member "old-c"
        unset member
        set member "new-a" "new-b"
        append member "new-c"
        set exclude enable
        set exclude-member "blocked-a"
        append exclude-member "blocked-b"
        set type folder
        set color 12
    next
    edit "dynamic-source"
        set member "static-evidence"
        set category ztna-ems-tag
        set filter "tag == quarantine"
        config tagging
            edit "migration"
                set category "source"
                set tags "quarantine" "endpoint"
            next
        end
    next
    edit "bad-color-group"
        set member "member-a"
        set color future-color
    next
end
"""

    parsed = parse_fortigate_config(content)
    groups = _by_name(parsed.address_groups)

    ordered = groups["ordered-static"]
    assert ordered.member == ["new-a", "new-b", "new-c"]
    assert ordered.exclude == "enable"
    assert ordered.exclude_member == ["blocked-a", "blocked-b"]
    assert ordered.type == "folder"
    assert ordered.color == 12

    dynamic = groups["dynamic-source"]
    assert dynamic.member == ["static-evidence"]
    assert dynamic.dynamic_filter == "tag == quarantine"
    assert dynamic.category == "ztna-ems-tag"
    assert dynamic.extra_settings["filter"] == "tag == quarantine"
    assert len(dynamic.tagging) == 1
    assert dynamic.tagging[0].name == "migration"
    assert dynamic.tagging[0].category == "source"
    assert dynamic.tagging[0].tags == ["quarantine", "endpoint"]

    bad_color = groups["bad-color-group"]
    assert bad_color.color is None
    assert bad_color.extra_settings["unparsed_color"] == "future-color"
