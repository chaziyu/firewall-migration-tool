from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _transform(config: str):
    fg = parse_fortigate_config(config)
    return fg, FGToIRTransformer(fg).transform()


def test_numeric_edit_id_is_not_policy_name_but_explicit_numeric_name_survives():
    fg, ir = _transform(
        """
config firewall policy
    edit 100
        set action accept
    next
    edit 101
        set name "101"
        set action accept
    next
end
"""
    )

    assert (fg.policies[0].id, fg.policies[0].name) == (100, None)
    assert ir.policies[0].name == "Rule_100"
    assert (fg.policies[1].id, fg.policies[1].name) == (101, "101")


def test_logtraffic_does_not_imply_log_start_and_explicit_start_survives():
    _, ir = _transform(
        """
config firewall policy
    edit 1
        set action accept
        set logtraffic all
    next
    edit 2
        set action accept
        set logtraffic all
        set logtraffic-start enable
    next
end
"""
    )

    first, second = ir.policies
    assert first.source_log_setting == "all"
    assert first.source_log_start_setting is None
    assert first.log_start is False
    assert first.log_end is True
    assert second.source_log_start_setting == "enable"
    assert second.log_start is True


def test_policy_source_semantics_are_preserved_without_unsafe_normalization():
    fg, ir = _transform(
        """
config firewall policy
    edit 100
        set name "All Semantics"
        set uuid "7fba"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "IPv4 Source"
        set srcaddr-negate enable
        set srcaddr6 "IPv6 Source A" "IPv6 Source B"
        set srcaddr6-negate enable
        set dstaddr "IPv4 Destination"
        set dstaddr-negate enable
        set dstaddr6 "IPv6 Destination"
        set dstaddr6-negate enable
        set groups "Group A" "Group B"
        set users "alice" "bob"
        set service "HTTPS" "DNS"
        set service-negate enable
        set action ipsec
        set vpntunnel "HQ-VPN"
        set schedule "workhours"
        set logtraffic all
        set logtraffic-start enable
        set nat enable
        set ippool enable
        set poolname "Pool A" "Pool B"
        set poolname6 "Pool6 A" "Pool6 B"
        set utm-status enable
        set av-profile "default-av"
        set ips-sensor "default-ips"
        set webfilter-profile "default-web"
        set application-list "default-app"
        set ssl-ssh-profile "certificate-inspection"
        set profile-type group
        set profile-group "Corporate Security"
        set profile-protocol-options "protocol-options"
        set internet-service enable
        set internet-service-name "Google" "Microsoft"
        set internet-service-custom "Custom A" "Custom B"
        set network-service-dynamic "Dynamic A" "Dynamic B"
        set inspection-mode proxy
        set ztna-status enable
        set ztna-ems-tag "Tag A" "Tag B"
        set timeout-send-rst enable
        set auto-asic-offload disable
        set np-acceleration enable
        set port-preserve disable
    next
end
"""
    )

    source = fg.policies[0]
    policy = ir.policies[0]
    assert source.extra_settings["internet_service_custom"] == ["Custom A", "Custom B"]
    assert source.extra_settings["network_service_dynamic"] == ["Dynamic A", "Dynamic B"]
    assert source.timeout_send_rst == "enable"
    assert source.auto_asic_offload == "disable"
    assert source.np_acceleration == "enable"
    assert source.port_preserve == "disable"
    assert policy.action == PolicyAction.IPSEC
    assert policy.source_action == "ipsec"
    assert policy.source_vpn_tunnel == "HQ-VPN"
    assert policy.source_ipv6_address_references == ["IPv6 Source A", "IPv6 Source B"]
    assert policy.destination_ipv6_address_references == ["IPv6 Destination"]
    assert policy.source == ["IPv4 Source"]
    assert policy.destination == []
    assert policy.service == []
    assert policy.destination_address_references == ["IPv4 Destination"]
    assert policy.source_service_references == ["HTTPS", "DNS"]
    assert policy.source_address_negate_setting == "enable"
    assert policy.destination_address_negate_setting == "enable"
    assert policy.source_ipv6_address_negate_setting == "enable"
    assert policy.destination_ipv6_address_negate_setting == "enable"
    assert policy.source_service_negate_setting == "enable"
    assert policy.nat_pool_names6 == ["Pool6 A", "Pool6 B"]
    assert policy.antivirus == "default-av"
    assert policy.ips_sensor == "default-ips"
    assert policy.webfilter == "default-web"
    assert policy.application_list == "default-app"
    assert policy.ssl_ssh_profile == "certificate-inspection"
    assert policy.source_profile_type == "group"
    assert policy.source_profile_group == "Corporate Security"
    assert policy.source_profile_protocol_options == "protocol-options"
    assert policy.security_profile_group is None
    assert policy.source_internet_service_status == "enable"
    assert policy.internet_service == ["Google", "Microsoft"]
    assert policy.source_timeout_send_rst == "enable"
    assert policy.source_auto_asic_offload == "disable"
    assert policy.source_np_acceleration == "enable"
    assert policy.source_port_preserve == "disable"
    assert policy.source_effective_timeout_send_rst == "enable"
    assert policy.source_effective_auto_asic_offload == "disable"
    assert policy.source_effective_np_acceleration == "enable"
    assert policy.source_effective_port_preserve == "disable"
    assert policy.source_extra_settings == source.extra_settings
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True


def test_explicit_profiles_survive_without_utm_status():
    _, ir = _transform(
        """
config firewall policy
    edit 10
        set action accept
        set av-profile "av"
        set ips-sensor "ips"
        set webfilter-profile "web"
        set application-list "app"
        set ssl-ssh-profile "ssl"
    next
end
"""
    )

    policy = ir.policies[0]
    assert (
        policy.antivirus,
        policy.ips_sensor,
        policy.webfilter,
        policy.application_list,
        policy.ssl_ssh_profile,
    ) == ("av", "ips", "web", "app", "ssl")
    assert policy.security_profile_group is None
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False


def test_unknown_action_fails_closed_and_requires_review():
    _, ir = _transform(
        """
config firewall policy
    edit 9
        set action vendor-future-action
    next
end
"""
    )

    policy = ir.policies[0]
    assert policy.source_action == "vendor-future-action"
    assert policy.action == PolicyAction.DENY
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True
