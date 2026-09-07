from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.phase_28_30_extensions import (
    FGOnetimeSchedule746,
    FGPhase1Interface746,
    FGPhase1Policy746,
    FGPhase2Interface746,
    FGPhase2Policy746,
    FGRecurringSchedule746,
    FGScheduleGroup746,
)


def test_phase28_recurring_onetime_and_group_models_stay_distinct_and_raw():
    config = parse_fortigate_config('''
config firewall schedule recurring
    edit "Business Hours"
        set day monday tuesday wednesday thursday friday
        set start 08:30
        set end 17:45
        set color 5
        set fabric-object enable
    next
end
config firewall schedule onetime
    edit "Change Window 1"
        set start "23:00 2026/09/10"
        set end "01:30 2026/09/11"
        set start-utc "1789071600"
        set end-utc "1789080600"
        set expiration-days 7
        set color 8
        set fabric-object disable
    next
end
config firewall schedule group
    edit "Maintenance Windows"
        set member "Business Hours" "Change Window 1"
        set color 9
        set fabric-object enable
    next
end
''')

    recurring, onetime = config.schedules
    assert isinstance(recurring, FGRecurringSchedule746)
    assert not isinstance(recurring, FGOnetimeSchedule746)
    assert recurring.name == "Business Hours"
    assert recurring.day == [
        "monday", "tuesday", "wednesday", "thursday", "friday"
    ]
    assert (recurring.start, recurring.end) == ("08:30", "17:45")
    assert (recurring.color, recurring.fabric_object) == (5, "enable")

    assert isinstance(onetime, FGOnetimeSchedule746)
    assert onetime.name == "Change Window 1"
    assert onetime.type == "onetime"
    assert onetime.start == "23:00 2026/09/10"
    assert onetime.end == "01:30 2026/09/11"
    assert onetime.start_utc == "1789071600"
    assert onetime.end_utc == "1789080600"
    assert onetime.expiration_days == 7

    group = config.schedule_groups[0]
    assert isinstance(group, FGScheduleGroup746)
    assert group.name == "Maintenance Windows"
    assert group.member == ["Business Hours", "Change Window 1"]
    assert (group.color, group.fabric_object) == (9, "enable")


def test_phase29_phase1_modes_keep_identity_fields_order_and_secret_safety():
    content = '''
config vpn ipsec phase1-interface
    edit "route-v6"
        set interface "wan1"
        set ip-version 6
        set local-gw6 2001:db8:1::1
        set remote-gw6 2001:db8:2::1
        set ike-version 2
        set peertype any
        set proposal aes256-sha256 aes128-sha256
        set dhgrp 14 19
        set authmethod signature
        set certificate "vpn-cert-a" "vpn-cert-b"
        set cert-trust-store local
        set cert-peer-username-validation rfc822name
        set localid "branch.example"
        set localid-type fqdn
        set dpd on-idle
        set dpd-retrycount 4
        set nattraversal enable
        set aggregate-member enable
        set aggregate-weight 20
    next
end
config vpn ipsec phase1
    edit "policy-dialup"
        set ip-version 4
        set remote-gw-match iprange
        set remote-gw-start-ip 198.51.100.10
        set remote-gw-end-ip 198.51.100.20
        set remote-gw-country MY
        set remote-gw-ztna-tags "trusted-device" "managed-device"
        set ike-version 2
        set peertype any
        set proposal aes256-sha256 aes128-sha256
        set dhgrp 19 14
        set authmethod psk
        set psksecret "DO_NOT_EXPORT_PHASE29_SECRET"
        set authusrgrp "vpn-users"
        set mode-cfg enable
        set ipv4-start-ip 10.10.10.10
        set ipv4-end-ip 10.10.10.50
        set dns-suffix-search "corp.example" "vpn.example"
    next
end
'''
    config = parse_fortigate_config(content)

    interface = config.phase1_interfaces[0]
    policy = config.phase1_policies[0]
    assert isinstance(interface, FGPhase1Interface746)
    assert isinstance(policy, FGPhase1Policy746)
    assert type(interface) is not type(policy)

    assert interface.ip_version == "6"
    assert interface.proposal == ["aes256-sha256", "aes128-sha256"]
    assert interface.dhgrp == [14, 19]
    assert interface.certificate == ["vpn-cert-a", "vpn-cert-b"]
    assert interface.cert_trust_store == "local"
    assert interface.cert_peer_username_validation == "rfc822name"
    assert interface.aggregate_weight == 20

    assert policy.ip_version == "4"
    assert policy.remote_gw_match == "iprange"
    assert policy.remote_gw_start_ip == "198.51.100.10"
    assert policy.remote_gw_end_ip == "198.51.100.20"
    assert policy.remote_gw_country == "MY"
    assert policy.remote_gw_ztna_tags == ["trusted-device", "managed-device"]
    assert policy.proposal == ["aes256-sha256", "aes128-sha256"]
    assert policy.dhgrp == [19, 14]
    assert policy.dns_suffix_search == ["corp.example", "vpn.example"]
    assert policy.has_psk is True
    assert "DO_NOT_EXPORT_PHASE29_SECRET" not in config.model_dump_json()


def test_phase30_phase2_modes_preserve_ipv4_ipv6_named_and_range_selectors():
    config = parse_fortigate_config('''
config vpn ipsec phase2-interface
    edit "route-selectors"
        set phase1name "route-v6"
        set proposal aes256-sha256 aes128-sha256
        set pfs enable
        set dhgrp 19 14
        set keylife-type both
        set keylifeseconds 3600
        set keylifekbs 512000
        set replay enable
        set auto-negotiate enable
        set src-addr-type name
        set src-name "LOCAL_V4" "LOCAL_V4_2"
        set dst-addr-type subnet
        set dst-subnet 10.20.0.0 255.255.0.0
        set src-subnet6 2001:db8:10::/64
        set dst-subnet6 2001:db8:20::/64
        set protocol 6
        set src-port 1024
        set dst-port 443
        set add-route phase1
    next
end
config vpn ipsec phase2
    edit "policy-selectors"
        set phase1name "policy-dialup"
        set proposal aes256-sha256
        set pfs enable
        set dhgrp 14
        set src-addr-type range
        set src-start-ip 192.0.2.10
        set src-end-ip 192.0.2.99
        set dst-addr-type range
        set dst-start-ip6 2001:db8:30::10
        set dst-end-ip6 2001:db8:30::ff
        set src-name6 "LOCAL_V6"
        set dst-name6 "REMOTE_V6"
        set protocol 17
        set src-port 500
        set dst-port 500
    next
end
''')

    interface = config.phase2_interfaces[0]
    policy = config.phase2_policies[0]
    assert isinstance(interface, FGPhase2Interface746)
    assert isinstance(policy, FGPhase2Policy746)
    assert type(interface) is not type(policy)

    assert interface.phase1name == "route-v6"
    assert interface.proposal == ["aes256-sha256", "aes128-sha256"]
    assert interface.dhgrp == [19, 14]
    assert interface.src_name == ["LOCAL_V4", "LOCAL_V4_2"]
    assert interface.dst_subnet == "10.20.0.0 255.255.0.0"
    assert interface.src_subnet6 == "2001:db8:10::/64"
    assert interface.dst_subnet6 == "2001:db8:20::/64"
    assert (interface.protocol, interface.src_port, interface.dst_port) == (6, 1024, 443)
    assert interface.add_route == "phase1"

    assert policy.phase1name == "policy-dialup"
    assert policy.src_addr_type == "range"
    assert (policy.src_start_ip, policy.src_end_ip) == (
        "192.0.2.10", "192.0.2.99"
    )
    assert (policy.dst_start_ip6, policy.dst_end_ip6) == (
        "2001:db8:30::10", "2001:db8:30::ff"
    )
    assert policy.src_name6 == ["LOCAL_V6"]
    assert policy.dst_name6 == ["REMOTE_V6"]
    assert (policy.protocol, policy.src_port, policy.dst_port) == (17, 500, 500)
