from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_policy_based_ngfw_is_typed_separately_with_profiles_and_mode():
    content = '''
config system settings
    set ngfw-mode policy-based
end
config firewall security-policy
    edit 7
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "inside"
        set dstaddr "all"
        set service "HTTPS"
        set application "Web.Client" "DNS"
        set av-profile "default"
        set ips-sensor "protect"
        set webfilter-profile "standard"
    next
end
'''
    result = extract_fortigate_config(content)
    policy = parse_fortigate_config(content).security_policies[0]
    assert policy.srcaddr == ["inside"]
    assert policy.application == ["Web.Client", "DNS"]
    assert policy.ngfw_mode == "policy-based"
    assert policy.settings["av_profile"] == "default"
    assert policy.settings["ips_sensor"] == "protect"
    section = next(s for s in result.source_sections if s.path == "firewall security-policy")
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_traffic_shaper_and_shaping_policy_keep_semantics():
    config = parse_fortigate_config('''
config firewall shaper traffic-shaper
    edit "gold"
        set guaranteed-bandwidth 100
        set maximum-bandwidth 1000
        set bandwidth-unit kbps
        set dscp-marking enable
        set dscp-marking-value 46
        set cos-marking enable
        set cos-marking-value 5
        set exceed-action red
        set exceed-class-id 3
        set overhead enable
    next
end
config firewall shaping-policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "inside"
        set dstaddr "outside"
        set service "HTTPS"
        set traffic-shaper "gold"
        set traffic-shaper-reverse "gold"
    next
end
''')
    shaper = config.traffic_shapers[0]
    assert (shaper.guaranteed_bandwidth, shaper.maximum_bandwidth) == (100, 1000)
    assert shaper.dscp_marking_value == "46"
    assert shaper.cos_marking_value == "5"
    assert shaper.exceed_class_id == 3
    policy = config.shaping_policies[0]
    assert policy.srcaddr == ["inside"]
    assert policy.traffic_shaper_reverse == "gold"


def test_service_ports_support_ranges_qualified_ports_and_malformed_fallback():
    config = parse_fortigate_config('''
config firewall service custom
    edit "web"
        set tcp-portrange 443 8000-8010 1000-1002:2000-2002
        set udp-portrange bad-range
    next
end
''')
    service = config.services[0]
    assert [item.port for item in service.tcp_port_ranges[:1]] == [443]
    assert service.tcp_port_ranges[1].destination_start == 8000
    qualified = service.tcp_port_ranges[2]
    assert (qualified.source_start, qualified.destination_end) == (1000, 2002)
    assert service.udp_port_ranges[0].original == "bad-range"
    assert service.udp_port_ranges[0].port is None


def test_phase1_interface_and_policy_mode_are_typed_and_secret_safe():
    config = parse_fortigate_config('''
config vpn ipsec phase1-interface
    edit "route-vpn"
        set interface "wan1"
        set proposal aes256-sha256
        set dhgrp 14 19
        set authmethod signature
        set certificate "vpn-cert"
        set nattraversal enable
        set dpd on-demand
        set dpd-retrycount 3
        set psksecret "never-export-this"
    next
end
config vpn ipsec phase1
    edit "policy-vpn"
        set ike-version 2
        set proposal aes256-sha256
        set dhgrp 14 19
        set authmethod psk
        set localid "branch-a"
        set dpd-retryinterval 30
    next
end
''')
    interface = config.phase1_interfaces[0]
    assert interface.dhgrp == [14, 19]
    assert interface.authmethod == "signature"
    assert interface.has_psk is True
    assert "never-export-this" not in config.model_dump_json()
    policy = config.phase1_policies[0]
    assert policy.ike_version == "2"
    assert policy.dhgrp == [14, 19]
    assert policy.dpd_retryinterval == 30
