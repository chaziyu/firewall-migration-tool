import pytest

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_phase16_local_in_metadata_is_typed_and_stays_source_only():
    content = """
config firewall local-in-policy
    edit 10
        set status disable
        set intf "wan2" "wan1"
        set srcaddr "ADMIN1" "ADMIN2"
        set dstaddr "all"
        set service "HTTPS" "SSH"
        set schedule "always"
        set action accept
        set comments "IPv4 management rule"
        set uuid "local-in-v4-uuid"
        set virtual-patch enable
        set ha-mgmt-intf-only enable
    next
end
config firewall local-in-policy6
    edit 20
        set intf "wan6"
        set srcaddr "ADMIN6"
        set dstaddr "all"
        set service "HTTPS"
        set comments "IPv6 management rule"
        set uuid "local-in-v6-uuid"
        set virtual-patch disable
    next
end
"""
    parsed = parse_fortigate_config(content)
    ipv4, ipv6 = parsed.local_in_policies

    assert ipv4.address_family == "ipv4"
    assert ipv4.intf == ["wan2", "wan1"]
    assert ipv4.comments == "IPv4 management rule"
    assert ipv4.uuid == "local-in-v4-uuid"
    assert ipv4.virtual_patch == "enable"
    assert ipv4.ha_mgmt_intf_only == "enable"
    assert ipv4.status == "disable"

    assert ipv6.address_family == "ipv6"
    assert ipv6.comments == "IPv6 management rule"
    assert ipv6.uuid == "local-in-v6-uuid"
    assert ipv6.virtual_patch == "disable"
    assert ipv6.ha_mgmt_intf_only is None

    result = extract_fortigate_config(content)
    assert [rule.family for rule in result.canonical_ir.local_in_policies] == [
        "local-in-policy-ipv4",
        "local-in-policy-ipv6",
    ]
    assert result.canonical_ir.policies == []
    assert result.canonical_ir.nat_rules == []
    assert result.generation_safe is False


@pytest.mark.parametrize("ngfw_mode", ["policy-based", "profile-based", None])
def test_phase17_security_policy_survives_all_ngfw_context_states(ngfw_mode):
    settings = (
        f"config system settings\n    set ngfw-mode {ngfw_mode}\nend\n"
        if ngfw_mode is not None
        else ""
    )
    content = settings + """
config firewall security-policy
    edit 7
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set application "Web.Client"
        set groups "engineering"
        set action accept
    next
end
"""

    parsed = parse_fortigate_config(content)
    assert len(parsed.security_policies) == 1
    assert parsed.security_policies[0].ngfw_mode == ngfw_mode
    assert parsed.policies == []

    result = extract_fortigate_config(content)
    assert result.canonical_ir.policies == []
    assert len(result.canonical_ir.security_policies) == 1
    assert result.canonical_ir.security_policies[0].family == "security-policy"
    assert result.generation_safe is False


def test_phase17_ngfw_mode_is_scoped_per_vdom():
    content = """
config vdom
edit root
    config system settings
        set ngfw-mode policy-based
    end
    config firewall security-policy
        edit 1
            set srcintf "any"
            set dstintf "any"
            set srcaddr "all"
            set dstaddr "all"
            set service "ALL"
        next
    end
next
edit tenant
    config system settings
        set ngfw-mode profile-based
    end
    config firewall security-policy
        edit 2
            set srcintf "any"
            set dstintf "any"
            set srcaddr "all"
            set dstaddr "all"
            set service "ALL"
        next
    end
next
end
"""
    parsed = parse_fortigate_config(content)
    assert [(p.source_context, p.ngfw_mode) for p in parsed.security_policies] == [
        ("root", "policy-based"),
        ("tenant", "profile-based"),
    ]


@pytest.mark.parametrize(
    ("protocol_line", "expected_protocol", "expected_unparsed"),
    [
        ("set protocol 6", 6, None),
        ("", None, None),
        ("set protocol not-a-number", None, "not-a-number"),
    ],
)
def test_phase18_central_snat_protocol_is_safe_integer(
    protocol_line, expected_protocol, expected_unparsed
):
    content = f"""
config firewall central-snat-map
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set orig-addr "all"
        set dst-addr "all"
        {protocol_line}
        set orig-port "100-200"
        set dst-port "443"
        set nat-port "1024-2048"
    next
end
"""
    parsed = parse_fortigate_config(content)
    rule = parsed.central_snat_rules[0]

    assert rule.protocol == expected_protocol
    assert rule.orig_port == "100-200"
    assert rule.dst_port == "443"
    assert rule.nat_port == "1024-2048"
    if expected_unparsed is None:
        assert "unparsed_protocol" not in rule.extra_settings
    else:
        assert rule.extra_settings["unparsed_protocol"] == expected_unparsed
        result = extract_fortigate_config(content)
        assert len(result.canonical_ir.central_snat_rules) == 1
        assert result.generation_safe is False


def test_phase19_ip_pool_malformed_numeric_values_are_preserved():
    content = """
config firewall ippool
    edit "CGN_POOL"
        set type port-block-allocation
        set startip 203.0.113.10
        set endip 203.0.113.20
        set block-size broken
        set num-blocks-per-user 8
        set pba-timeout 300
        set port-per-user 256
        set cgn-port-start invalid-port
        set cgn-port-end 65535
        set exclude-ip 203.0.113.11 203.0.113.12
    next
end
"""
    parsed = parse_fortigate_config(content)
    pool = parsed.ip_pools[0]

    assert pool.type == "port-block-allocation"
    assert pool.block_size is None
    assert pool.num_blocks_per_user == 8
    assert pool.pba_timeout == 300
    assert pool.port_per_user == 256
    assert pool.cgn_port_start is None
    assert pool.cgn_port_end == 65535
    assert pool.exclude_ip == ["203.0.113.11", "203.0.113.12"]
    assert pool.extra_settings["unparsed_block_size"] == "broken"
    assert pool.extra_settings["unparsed_cgn_port_start"] == "invalid-port"

    result = extract_fortigate_config(content)
    assert len(result.canonical_ir.ip_pools) == 1
    assert result.canonical_ir.ip_pools[0].requires_manual_review is True


def test_phase20_vip_realserver_malformed_numbers_do_not_drop_backends():
    content = """
config firewall vip
    edit "LB_VIP"
        set type server-load-balance
        set extip 203.0.113.50
        set color invalid-color
        config realservers
            edit 1
                set ip 10.0.0.10
                set port bad-port
                set weight 10
                set holddown-interval 30
            next
            edit 2
                set ip 10.0.0.11
                set port 8443
                set weight bad-weight
            next
        end
    next
end
config firewall vipgrp
    edit "ORDERED"
        set member "VIP_A" "VIP_B" "VIP_C"
    next
end
"""
    parsed = parse_fortigate_config(content)
    vip = parsed.vips[0]

    assert vip.color is None
    assert vip.extra_settings["unparsed_color"] == "invalid-color"
    assert [server.id for server in vip.realservers] == [1, 2]
    assert vip.realservers[0].port is None
    assert vip.realservers[0].extra_settings["unparsed_port"] == "bad-port"
    assert vip.realservers[0].weight == 10
    assert vip.realservers[1].port == 8443
    assert vip.realservers[1].weight is None
    assert vip.realservers[1].extra_settings["unparsed_weight"] == "bad-weight"
    assert parsed.vip_groups[0].member == ["VIP_A", "VIP_B", "VIP_C"]

    result = extract_fortigate_config(content)
    assert len(result.canonical_ir.virtual_ips) == 1
    assert len(result.canonical_ir.virtual_ips[0].real_servers) == 2
    assert result.canonical_ir.virtual_ips[0].requires_manual_review is True
    assert result.canonical_ir.virtual_ip_groups[0].members == [
        "VIP_A",
        "VIP_B",
        "VIP_C",
    ]
