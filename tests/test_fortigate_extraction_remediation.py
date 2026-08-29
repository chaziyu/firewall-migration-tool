from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate import FortiGateSourceParser
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_parse_is_authoritative_extraction_ir():
    content = """config firewall address
    edit "lan"
        set subnet 10.0.0.0 255.255.255.0
    next
end
"""
    parser = FortiGateSourceParser()
    parsed = parser.parse(content).model_dump()
    extracted = parser.extract(content).canonical_ir.model_dump()
    parsed["metadata"].pop("migration_timestamp")
    extracted["metadata"].pop("migration_timestamp")
    assert parsed == extracted


def test_vdom_paths_and_duplicate_names_retain_context():
    content = """config vdom
edit root
    config firewall address
        edit "duplicate"
            set subnet 10.0.0.0 255.255.255.0
        next
    end
next
edit tenant
    config firewall address
        edit "duplicate"
            set subnet 10.1.0.0 255.255.255.0
        next
    end
next
end
"""
    result = extract_fortigate_config(content)
    assert [(item.name, item.source_context) for item in result.canonical_ir.addresses] == [
        ("duplicate", "root"),
        ("duplicate", "tenant"),
    ]
    address_sections = [s for s in result.source_sections if s.path == "firewall address"]
    assert {s.source_context for s in address_sections} == {"root", "tenant"}
    assert all(not s.path.startswith("vdom ") for s in result.source_sections)


def test_vdom_duplicate_vip_names_resolve_only_within_policy_context():
    content = """config vdom
edit root
    config firewall vip
        edit "shared-vip"
            set extip 203.0.113.1
            set mappedip 10.0.0.1
        next
    end
    config firewall policy
        edit 1
            set srcintf "any"
            set dstintf "any"
            set srcaddr "all"
            set dstaddr "shared-vip"
            set service "ALL"
            set action accept
        next
    end
next
edit tenant
    config firewall vip
        edit "shared-vip"
            set extip 203.0.113.2
            set mappedip 10.1.0.1
        next
    end
    config firewall policy
        edit 1
            set srcintf "any"
            set dstintf "any"
            set srcaddr "all"
            set dstaddr "shared-vip"
            set service "ALL"
            set action accept
        next
    end
next
end
"""
    result = extract_fortigate_config(content)
    assert [
        (rule.source_context, rule.destination, rule.translated_destinations)
        for rule in result.canonical_ir.nat_rules
    ] == [
        ("root", ["203.0.113.1"], ["10.0.0.1"]),
        ("tenant", ["203.0.113.2"], ["10.1.0.1"]),
    ]
    assert result.generation_safe is False
    assert any("Multiple FortiGate VDOMs" in reason for reason in result.blocking_reasons)


def test_central_nat_suppresses_policy_derived_nat_and_preserves_rules():
    content = """config system settings
    set central-nat enable
end
config firewall central-snat-map
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set orig-addr "src"
        set dst-addr "all"
        set nat-ippool "pool"
        set comments "ordered source NAT"
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "src"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set nat enable
    next
end
"""
    result = extract_fortigate_config(content)
    assert result.canonical_ir.nat_rules == []
    assert result.canonical_ir.central_snat_rules[0].source_id == "1"
    assert result.generation_safe is False
    assert any("central NAT" in reason for reason in result.blocking_reasons)


def test_policy_based_ngfw_security_policy_is_distinct_and_blocking():
    content = """config system settings
    set ngfw-mode policy-based
end
config firewall security-policy
    edit 7
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set application "Web.Client"
        set action accept
    next
end
"""
    result = extract_fortigate_config(content)
    assert result.canonical_ir.policies == []
    assert result.canonical_ir.security_policies[0].family == "security-policy"
    assert result.migration_complete is False
    assert result.generation_safe is False


def test_internet_service_and_unknown_policy_semantics_force_review():
    content = """config firewall policy
    edit 3
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "ordinary-source"
        set dstaddr "ordinary-destination"
        set service "HTTPS"
        set internet-service enable
        set internet-service-name "Google"
        set timeout-send-rst enable
        set action accept
    next
end
"""
    result = extract_fortigate_config(content)
    policy = result.canonical_ir.policies[0]
    assert policy.requires_manual_review is True
    assert policy.safe_for_target_generation is False
    assert policy.source_internet_service_settings
    assert any("unknown traffic-affecting" in reason for reason in policy.review_reasons)


def test_source_only_rule_families_do_not_become_transit_policy_or_static_route():
    content = """config router policy
    edit 1
        set input-device "lan"
        set src "10.0.0.0/24"
        set dst "0.0.0.0/0"
        set gateway 192.0.2.1
        set output-device "wan"
    next
end
config firewall local-in-policy
    edit 2
        set intf "wan"
        set srcaddr "admin-net"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
    next
end
config firewall proxy-policy
    edit 3
        set proxy explicit-web
        set srcaddr "all"
        set dstaddr "all"
        set service "webproxy"
        set action accept
    next
end
"""
    result = extract_fortigate_config(content)
    ir = result.canonical_ir
    assert ir.routes == []
    assert ir.policies == []
    assert [rule.family for rule in ir.policy_routes] == ["policy-route-ipv4"]
    assert [rule.family for rule in ir.local_in_policies] == ["local-in-policy-ipv4"]
    assert [rule.family for rule in ir.proxy_policies] == ["proxy-policy"]
    assert result.migration_complete is False
    assert result.generation_safe is False
    assert any("policy-route-ipv4" in reason for reason in result.blocking_reasons)
    assert any("local-in-policy-ipv4" in reason for reason in result.blocking_reasons)
    assert any("proxy-policy" in reason for reason in result.blocking_reasons)
    assert all(item.requires_manual_review for item in result.inventory_items)


def test_dhcpv6_and_source_only_firewall_dependencies_block_generation():
    content = """config system dhcp6 server
    edit 1
        set interface "lan"
        config ip-range
            edit 1
                set start-ip 2001:db8::10
                set end-ip 2001:db8::20
            next
        end
    next
end
config firewall ttl-policy
    edit 2
        set status enable
        set srcaddr "all"
        set service "ALL"
    next
end
"""
    result = extract_fortigate_config(content)
    assert result.canonical_ir.dhcp_servers == []
    assert [rule.family for rule in result.canonical_ir.dhcp6_servers] == ["dhcp6-server"]
    assert [rule.family for rule in result.canonical_ir.source_only_rules] == ["ttl-policy"]
    assert result.migration_complete is False
    assert result.generation_safe is False
    assert any("dhcp6-server" in reason for reason in result.blocking_reasons)
    assert any("ttl-policy" in reason for reason in result.blocking_reasons)
    assert all(item.requires_manual_review for item in result.inventory_items)


def test_session_ttl_default_and_interface_ipv6_are_preserved():
    content = """config system session-ttl
    set default 900
    config port
        edit 1
            set protocol 6
            set start-port 443
            set end-port 443
            set timeout 300
        next
    end
end
config system interface
    edit "lan"
        config ipv6
            set ip6-address 2001:db8::1/64
            set ip6-send-adv enable
            set ip6-manage-flag enable
        end
    next
end
"""
    ir = extract_fortigate_config(content).canonical_ir
    assert ir.session_ttl_settings.default_timeout_seconds == 900
    assert ir.session_ttl_overrides[0].timeout_seconds == 300
    assert ir.interfaces[0].ipv6_source_settings == {
        "ip6_address": "2001:db8::1/64",
        "ip6_send_adv": "enable",
        "ip6_manage_flag": "enable",
    }
    assert ir.interfaces[0].ip is None


def test_unsupported_traffic_section_blocks_generation():
    result = extract_fortigate_config("""config firewall mystery-policy
    edit 1
        set action accept
    next
end
""")
    assert result.source_sections[0].status == ExtractionStatus.UNSUPPORTED
    assert result.migration_complete is False
    assert result.generation_safe is False
