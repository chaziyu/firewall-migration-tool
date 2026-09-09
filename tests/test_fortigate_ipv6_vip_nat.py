from fwmigrate.ir.enums import NATType
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_vip6_semantics_and_policy_dnat_are_preserved() -> None:
    result = extract_fortigate_config('''
config firewall vip6
    edit "WEB-VIP6"
        set extip 2001:db8::10
        set extintf "wan"
        set mappedip 2001:db8:1::10 2001:db8:1::11
        set src-filter 2001:db8:2::/64
        set portforward enable
        set protocol tcp
        set extport 443
        set mappedport 8443
    next
end
config firewall policy
    edit 100
        set srcaddr6 "all"
        set dstaddr6 "WEB-VIP6"
        set service "ALL"
    next
end
''')
    vip = result.canonical_ir.virtual_ips[0]
    assert (vip.source_context, vip.external_interface) == ("root", "wan")
    assert vip.mapped_ips == ["2001:db8:1::10", "2001:db8:1::11"]
    assert vip.source_filters == ["2001:db8:2::/64"]
    assert vip.migration_status == "PARTIALLY_NORMALIZED"
    rule = result.canonical_ir.nat_rules[0]
    assert rule.type == NATType.DESTINATION
    assert (rule.source_policy_reference, rule.source_vip_reference) == ("100", "WEB-VIP6")
    assert rule.destination == ["2001:db8::10"]
    assert rule.translated_destinations == ["2001:db8:1::10", "2001:db8:1::11"]
    assert (rule.original_destination_port, rule.translated_port) == ("443", "8443")
    assert any(d.source_field == "dstaddr6-vip" and d.reference == "WEB-VIP6" and d.result == "RESOLVED" for d in result.dependencies)


def test_vipgrp6_expands_in_order_and_reports_missing_members() -> None:
    result = extract_fortigate_config('''
config firewall vip6
    edit "A"
        set extip 2001:db8::1
        set mappedip 2001:db8:1::1
    next
    edit "B"
        set extip 2001:db8::2
        set mappedip 2001:db8:1::2
    next
end
config firewall vipgrp6
    edit "G"
        set member "B" "MISSING" "A"
    next
end
config firewall policy
    edit 1
        set srcaddr6 "all"
        set dstaddr6 "G"
        set service "ALL"
    next
end
''')
    assert [rule.source_vip_reference for rule in result.canonical_ir.nat_rules] == ["B", "A"]
    assert all(rule.source_vip_group_reference == "G" for rule in result.canonical_ir.nat_rules)
    group = result.canonical_ir.virtual_ip_groups[0]
    assert group.members == ["B", "MISSING", "A"] and group.requires_manual_review
    assert any(d.source_path == "firewall vipgrp6" and d.reference == "MISSING" and d.result == "UNRESOLVED" for d in result.dependencies)


def test_vip6_correlation_is_vdom_scoped_and_combines_snat6() -> None:
    result = extract_fortigate_config('''
config vdom
    edit "tenant-a"
        config firewall vip6
            edit "WEB"
                set extip 2001:db8::10
                set mappedip 2001:db8:1::10
            next
        end
        config firewall ippool6
            edit "POOL6"
                set startip 2001:db8:2::1
                set endip 2001:db8:2::1
            next
        end
        config firewall policy
            edit 10
                set srcaddr6 "all"
                set dstaddr6 "WEB"
                set service "ALL"
                set nat enable
                set ippool enable
                set poolname6 "POOL6"
            next
        end
    next
    edit "tenant-b"
        config firewall policy
            edit 20
                set srcaddr6 "all"
                set dstaddr6 "WEB"
                set service "ALL"
            next
        end
    next
end
''')
    assert len(result.canonical_ir.nat_rules) == 1
    rule = result.canonical_ir.nat_rules[0]
    assert (rule.type, rule.source_context) == (NATType.TWICE, "tenant-a")
    assert rule.translated_sources == ["2001:db8:2::1"]
