from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_ping_serv_status_uses_exact_cli_name_and_integer_type() -> None:
    parsed = parse_fortigate_config(
        """config system interface
    edit "port1"
        set ping-serv-status 3
        config secondaryip
            edit 1
                set ip 192.0.2.1 255.255.255.0
                set ping-serv-status 4
            next
        end
    next
end
"""
    )

    interface = parsed.interfaces[0]
    assert interface.ping_serv_status == 3
    assert interface.secondary_ips[0].ping_serv_status == 4
    assert "ping_serv_status" in interface.source_explicit_fields
    assert interface.source_attributes["ping_serv_status"] == 3


def test_src_vip_filter_is_typed_and_preserved_in_vip_and_nat_ir() -> None:
    parsed = parse_fortigate_config(
        """config system interface
    edit "WAN"
        set ip 203.0.113.1 255.255.255.0
    next
    edit "LAN"
        set ip 10.0.0.1 255.255.255.0
    next
end
config system zone
    edit "WAN"
        set interface "WAN"
    next
    edit "LAN"
        set interface "LAN"
    next
end
config firewall vip
    edit "WEB_VIP"
        set extip 203.0.113.10
        set mappedip "10.0.0.10"
        set extintf "WAN"
        set src-filter "TRUSTED_SOURCE"
        set src-vip-filter enable
    next
end
config firewall policy
    edit 10
        set srcintf "WAN"
        set dstintf "LAN"
        set srcaddr "all"
        set dstaddr "WEB_VIP"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
    )

    source_vip = parsed.vips[0]
    assert source_vip.src_vip_filter == "enable"

    ir = FGToIRTransformer(parsed).transform()
    virtual_ip = next(item for item in ir.virtual_ips if item.name == "WEB_VIP")
    assert virtual_ip.source_attributes["src_vip_filter"] == "enable"
    assert virtual_ip.requires_manual_review is True

    nat_rule = next(
        item for item in ir.nat_rules
        if item.source_vip_reference == "WEB_VIP"
    )
    assert nat_rule.source_attributes["src_vip_filter"] == "enable"
    assert nat_rule.requires_manual_review is True
    assert any("src-vip-filter" in reason for reason in nat_rule.review_reasons)


def test_firewall_policy_onetime_schedule_dependency_resolves() -> None:
    result = extract_fortigate_config(
        """config firewall schedule onetime
    edit "maintenance-window"
        set start "23:00 2026/09/10"
        set end "01:00 2026/09/11"
    next
end
config firewall policy
    edit 20
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "maintenance-window"
        set service "ALL"
    next
end
"""
    )

    dependency = next(
        item for item in result.dependencies
        if item.source_path == "firewall policy"
        and item.source_field == "schedule"
        and item.reference == "maintenance-window"
    )
    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall schedule onetime"
