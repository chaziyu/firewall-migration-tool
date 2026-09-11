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
        set srcaddr6 "inside-v6"
        set dstaddr6 "all-v6"
        set service "HTTPS"
        set application 12345 45678
        set app-category 10 20
        set app-group "web-apps"
        set groups "engineering" "operations"
        set users "alice" "bob"
        set av-profile "default"
        set casb-profile "casb"
        set diameter-filter-profile "diameter"
        set ips-sensor "protect"
        set webfilter-profile "standard"
        set ssl-ssh-profile "certificate-inspection"
        set virtual-patch-profile "virtual-patch"
        set waf-profile "waf"
        set schedule "business-hours"
        set logtraffic all
        set status disable
        set action deny
        set comments "NGFW rule"
    next
end
'''
    result = extract_fortigate_config(content)
    policy = parse_fortigate_config(content).security_policies[0]
    assert policy.srcaddr == ["inside"]
    assert policy.srcaddr6 == ["inside-v6"]
    assert policy.dstaddr6 == ["all-v6"]
    assert policy.application == [12345, 45678]
    assert "unparsed_application" not in policy.extra_settings
    assert policy.app_category == [10, 20]
    assert policy.app_group == ["web-apps"]
    assert policy.groups == ["engineering", "operations"]
    assert policy.users == ["alice", "bob"]
    assert policy.schedule == "business-hours"
    assert policy.logtraffic == "all"
    assert policy.status == "disable"
    assert policy.action == "deny"
    assert policy.comments == "NGFW rule"
    assert policy.ngfw_mode == "policy-based"
    assert policy.settings["av_profile"] == "default"
    assert policy.settings["ips_sensor"] == "protect"
    for field in ("casb_profile", "diameter_filter_profile", "virtual_patch_profile", "waf_profile"):
        assert getattr(policy, field) in {"casb", "diameter", "virtual-patch", "waf"}
        assert field not in policy.extra_settings
    section = next(s for s in result.source_sections if s.path == "firewall security-policy")
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_traffic_shaper_and_shaping_policy_keep_semantics():
    config = parse_fortigate_config('''
config firewall shaper traffic-shaper
    edit "gold"
        set guaranteed-bandwidth 100
        set maximum-bandwidth 1000
        set bandwidth-unit kbps
        set per-policy enable
        set diffserv enable
        set diffservcode 100000
        set dscp-marking-method multi-stage
        set exceed-bandwidth 500
        set exceed-dscp 111000
        set maximum-dscp 111111
        set dscp-marking enable
        set dscp-marking-value 46
        set cos-marking enable
        set cos-marking-method multi-stage
        set cos 110
        set exceed-cos 101
        set maximum-cos 100
        set cos-marking-value 5
        set exceed-action red
        set exceed-class-id 3
        set overhead 14
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
    assert shaper.per_policy == "enable"
    assert shaper.diffserv == "enable"
    assert shaper.diffservcode == "100000"
    assert shaper.dscp_marking_method == "multi-stage"
    assert shaper.exceed_bandwidth == 500
    assert shaper.exceed_dscp == "111000"
    assert shaper.maximum_dscp == "111111"
    assert shaper.cos == "110"
    assert shaper.cos_marking_method == "multi-stage"
    assert shaper.exceed_cos == "101"
    assert shaper.maximum_cos == "100"
    assert shaper.overhead == 14
    assert shaper.dscp_marking_value == "46"
    assert shaper.cos_marking_value == "5"
    assert shaper.exceed_class_id == 3

    result = extract_fortigate_config('''
config firewall shaper traffic-shaper
    edit "gold"
        set guaranteed-bandwidth 100
        set maximum-bandwidth 1000
        set bandwidth-unit kbps
        set per-policy enable
        set diffserv enable
        set diffservcode 100000
        set dscp-marking-method multi-stage
        set exceed-bandwidth 500
        set exceed-dscp 111000
        set maximum-dscp 111111
        set cos-marking enable
        set cos-marking-method multi-stage
        set cos 110
        set exceed-cos 101
        set maximum-cos 100
        set overhead 14
        set exceed-class-id 3
    next
end
''')
    section = next(item for item in result.source_sections if item.path == "firewall shaper traffic-shaper")
    assert section.status == ExtractionStatus.NORMALIZED
    policy = config.shaping_policies[0]
    assert policy.srcaddr == ["inside"]
    assert policy.traffic_shaper_reverse == "gold"


def test_policy_based_ngfw_dependencies_preserve_source_fields_and_audit_missing_refs():
    result = extract_fortigate_config('''
config webfilter profile
    edit "standard"
    next
end
config application group
    edit "web-apps"
    next
end
config user adgrp
    edit "engineering-fsso"
    next
end
config firewall internet-service-custom
    edit "custom-web"
    next
end
config firewall internet-service-custom-group
    edit "custom-group"
        set member "custom-web"
    next
end
config firewall security-policy
    edit 7
        set application 12345
        set app-group "web-apps" "missing-app"
        set fsso-groups "engineering-fsso" "missing-fsso"
        set internet-service-custom "custom-web" "missing-custom"
        set internet-service-src-custom "custom-web"
        set internet-service6-custom "custom-web"
        set internet-service6-src-custom "custom-web"
        set internet-service-custom-group "custom-group" "missing-group"
        set internet-service-src-custom-group "custom-group"
        set internet-service6-custom-group "custom-group"
        set internet-service6-src-custom-group "custom-group"
        set webfilter-profile "standard"
    next
    edit 8
        set webfilter-profile "missing-webfilter"
    next
end
''')

    policy_dependencies = {
        (item.source_field, item.reference): item
        for item in result.dependencies
        if item.source_path == "firewall security-policy"
    }
    assert policy_dependencies[("app-group", "web-apps")].result == "RESOLVED"
    assert policy_dependencies[("app-group", "web-apps")].target_path == "application group"
    assert policy_dependencies[("webfilter-profile", "standard")].result == "RESOLVED"
    assert policy_dependencies[("webfilter-profile", "standard")].target_path == "webfilter profile"
    assert policy_dependencies[("fsso-groups", "engineering-fsso")].result == "RESOLVED"
    assert policy_dependencies[("fsso-groups", "engineering-fsso")].target_path == "user adgrp"
    for field in (
        "internet-service-custom",
        "internet-service-src-custom",
        "internet-service6-custom",
        "internet-service6-src-custom",
    ):
        assert policy_dependencies[(field, "custom-web")].result == "RESOLVED"
        assert policy_dependencies[(field, "custom-web")].target_path == "firewall internet-service-custom"
    for field in (
        "internet-service-custom-group",
        "internet-service-src-custom-group",
        "internet-service6-custom-group",
        "internet-service6-src-custom-group",
    ):
        assert policy_dependencies[(field, "custom-group")].result == "RESOLVED"
        assert policy_dependencies[(field, "custom-group")].target_path == "firewall internet-service-custom-group"

    for field, reference in (
        ("app-group", "missing-app"),
        ("fsso-groups", "missing-fsso"),
        ("internet-service-custom", "missing-custom"),
        ("internet-service-custom-group", "missing-group"),
        ("webfilter-profile", "missing-webfilter"),
    ):
        dependency = policy_dependencies[(field, reference)]
        assert dependency.result == "UNRESOLVED"
        assert dependency.source_context == "root"
        assert dependency.source_object == ("8" if field == "webfilter-profile" else "7")
        assert dependency.target_path is None
    assert not any(item.source_field == "application" for item in result.dependencies)
    section = next(item for item in result.source_sections if item.path == "firewall security-policy")
    assert section.unresolved_dependencies == 5
    assert any("missing-app" in entry.message for entry in result.canonical_ir.audit_entries)
    ngfw_policies = {
        policy.source_id: policy for policy in result.canonical_ir.security_policies
    }
    assert ngfw_policies["7"].source_attributes["webfilter_profile"] == "standard"
    assert ngfw_policies["8"].source_attributes["webfilter_profile"] == "missing-webfilter"


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
    assert (
        qualified.destination_start,
        qualified.destination_end,
        qualified.source_start,
        qualified.source_end,
    ) == (1000, 1002, 2000, 2002)
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
