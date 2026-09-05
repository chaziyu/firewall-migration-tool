from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_virtual_wire_and_vdom_link_have_typed_topology_fields_and_fallbacks():
    config = parse_fortigate_config(
        '''config system virtual-wire-pair
    edit "vw-main"
        set member "port1" "port2"
        set outer-vlan-id 123
        set vlan-filtering enable
        set future-vwire-option keep
    next
end
config system vdom-link
    edit "link-main"
        set vdom "root"
        set peer "tenant-a"
        set vcluster enable
        set future-link-option keep
    next
end
'''
    )

    pair = config.virtual_wire_pairs[0]
    assert pair.members == ["port1", "port2"]
    assert pair.outer_vlan_id == 123
    assert pair.vlan_filtering == "enable"
    assert pair.extra_settings["future_vwire_option"] == "keep"

    link = config.vdom_links[0]
    assert link.vdom == "root"
    assert link.peer == "tenant-a"
    assert link.vcluster == "enable"
    assert link.extra_settings["future_link_option"] == "keep"


def test_policy_profile_references_are_typed_for_ipv4_ipv6_and_mixed_values():
    config = parse_fortigate_config(
        '''config firewall policy
    edit 1
        set av-profile "av4"
        set dnsfilter-profile "dns4"
        set dlp-sensor "dlp4"
        set profile-type group
        set profile-group "group4"
        set unknown-policy-option keep
    next
    edit 2
        set ssl-ssh-profile "ssl6"
        set ips-sensor "ips6"
        set file-filter-profile "file6"
        set virtual-patch-profile "patch6"
    next
    edit 3
        set av-profile "av-mixed"
        set webfilter-profile "web-mixed"
        set emailfilter-profile "mail-mixed"
        set sctp-filter-profile "sctp-mixed"
    next
end
'''
    )

    first, second, third = config.policies
    assert (first.av_profile, first.dnsfilter_profile, first.dlp_sensor) == (
        "av4", "dns4", "dlp4"
    )
    assert (first.profile_type, first.profile_group) == ("group", "group4")
    assert first.extra_settings["unknown_policy_option"] == "keep"
    assert (second.ssl_ssh_profile, second.ips_sensor, second.file_filter_profile) == (
        "ssl6", "ips6", "file6"
    )
    assert second.virtual_patch_profile == "patch6"
    assert (third.av_profile, third.webfilter_profile, third.emailfilter_profile) == (
        "av-mixed", "web-mixed", "mail-mixed"
    )
    assert third.sctp_filter_profile == "sctp-mixed"


def test_local_in_policy_uses_typed_fields_and_keeps_unknown_settings():
    config = parse_fortigate_config(
        '''config firewall local-in-policy6
    edit 9
        set status enable
        set intf "wan6" "mgmt6"
        set srcaddr "admin6" "vpn6"
        set dstaddr "firewall6"
        set service "HTTPS" "SSH"
        set schedule "always"
        set action accept
        set future-local-in-option preserve
    next
end
'''
    )

    rule = config.local_in_policies[0]
    assert rule.address_family == "ipv6"
    assert rule.intf == ["wan6", "mgmt6"]
    assert rule.srcaddr == ["admin6", "vpn6"]
    assert rule.dstaddr == ["firewall6"]
    assert rule.service == ["HTTPS", "SSH"]
    assert rule.schedule == "always"
    assert rule.action == "accept"
    assert rule.status == "enable"
    assert rule.extra_settings["future_local_in_option"] == "preserve"
    assert rule.settings["future_local_in_option"] == "preserve"
