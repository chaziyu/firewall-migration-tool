from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.model import FGPerIPShaper, FGShapingProfile
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_phase21_dos_anomaly_order_and_threshold_default_unset() -> None:
    content = """
config firewall DoS-policy
    edit 10
        set name "protect-edge"
        set status enable
        set interface "wan1"
        set srcaddr "all"
        set dstaddr "server-a"
        set service "HTTPS"
        config anomaly
            edit "tcp_syn_flood"
                set status enable
                set action block
                set threshold 3000
                set threshold(default) 1000
            next
            edit "udp_flood"
                set status enable
                set threshold 5000
                set threshold(default) 2000
                unset threshold(default)
            next
            edit "icmp_flood"
                set status disable
                set threshold(default) 700
            next
        end
    next
end
"""

    parsed = parse_fortigate_config(content)
    policy = parsed.dos_policies[0]

    assert policy.interface == "wan1"
    assert policy.srcaddr == ["all"]
    assert policy.dstaddr == ["server-a"]
    assert policy.service == ["HTTPS"]
    assert [item.name for item in policy.anomalies] == [
        "tcp_syn_flood",
        "udp_flood",
        "icmp_flood",
    ]

    syn, udp, icmp = policy.anomalies
    assert syn.threshold == 3000
    assert syn.threshold_default == 1000
    assert udp.threshold == 5000
    assert udp.threshold_default is None
    assert icmp.threshold is None
    assert icmp.threshold_default == 700
    assert "threshold(default)" not in udp.extra_settings
    assert "threshold_default" not in udp.extra_settings

    result = extract_fortigate_config(content)
    anomaly_section = next(
        section
        for section in result.source_sections
        if section.path == "firewall DoS-policy anomaly"
    )
    assert anomaly_section.status == ExtractionStatus.EXTRACT_ONLY
    assert anomaly_section.object_count_source == 3
    assert anomaly_section.object_count_parsed == 3


def test_phase22_per_ip_shaper_is_typed_and_preserves_unknown_settings() -> None:
    content = """
config firewall shaper per-ip-shaper
    edit "client-limit"
        set max-bandwidth 1000
        set bandwidth-unit mbps
        set max-concurrent-session 100
        set max-concurrent-tcp-session 60
        set max-concurrent-udp-session 40
        set diffserv-forward enable
        set diffserv-reverse disable
        set diffservcode-forward 101110
        set diffservcode-rev 001010
        set future-per-ip-setting "keep-me"
    next
end
"""

    parsed = parse_fortigate_config(content)
    assert len(parsed.per_ip_shapers) == 1
    shaper = parsed.per_ip_shapers[0]

    assert isinstance(shaper, FGPerIPShaper)
    assert shaper.name == "client-limit"
    assert shaper.max_bandwidth == 1000
    assert shaper.bandwidth_unit == "mbps"
    assert shaper.max_concurrent_session == 100
    assert shaper.max_concurrent_tcp_session == 60
    assert shaper.max_concurrent_udp_session == 40
    assert shaper.diffserv_forward == "enable"
    assert shaper.diffserv_reverse == "disable"
    assert shaper.diffservcode_forward == "101110"
    assert shaper.diffservcode_rev == "001010"
    assert shaper.extra_settings == {"future_per_ip_setting": "keep-me"}
    assert shaper.settings["future_per_ip_setting"] == "keep-me"

    result = extract_fortigate_config(content)
    section = next(
        item
        for item in result.source_sections
        if item.path == "firewall shaper per-ip-shaper"
    )
    assert section.status == ExtractionStatus.EXTRACT_ONLY
    assert section.object_count_source == 1
    assert section.object_count_parsed == 1


def test_phase22_shaping_profile_is_typed_with_ordered_nested_entries() -> None:
    content = """
config firewall shaping-profile
    edit "edge-profile"
        set type queuing
        set default-class-id 4
        set comment "WAN queue profile"
        set future-profile-setting "retain-top"
        config shaping-entries
            edit 1
                set class-id 4
                set priority high
                set guaranteed-bandwidth-percentage 30
                set maximum-bandwidth-percentage 80
                set limit 100
                set burst-in-msec 20
                set cburst-in-msec 30
                set red-probability 10
                set min 5
                set max 50
                set future-entry-setting "retain-child"
            next
            edit 2
                set class-id 7
                set priority medium
                set guaranteed-bandwidth-percentage 15
                set maximum-bandwidth-percentage 40
            next
        end
    next
end
"""

    parsed = parse_fortigate_config(content)
    assert len(parsed.shaping_profiles) == 1
    profile = parsed.shaping_profiles[0]

    assert isinstance(profile, FGShapingProfile)
    assert profile.name == "edge-profile"
    assert profile.type == "queuing"
    assert profile.default_class_id == 4
    assert profile.comment == "WAN queue profile"
    assert profile.extra_settings == {"future_profile_setting": "retain-top"}
    assert profile.nested_configs
    assert [entry.source_id for entry in profile.shaping_entries] == ["1", "2"]

    first, second = profile.shaping_entries
    assert first.id == 1
    assert first.class_id == 4
    assert first.priority == "high"
    assert first.guaranteed_bandwidth_percentage == 30
    assert first.maximum_bandwidth_percentage == 80
    assert first.limit == 100
    assert first.burst_in_msec == 20
    assert first.cburst_in_msec == 30
    assert first.red_probability == 10
    assert first.min == 5
    assert first.max == 50
    assert first.extra_settings == {"future_entry_setting": "retain-child"}
    assert second.id == 2
    assert second.class_id == 7
    assert second.priority == "medium"
    assert second.guaranteed_bandwidth_percentage == 15
    assert second.maximum_bandwidth_percentage == 40

    result = extract_fortigate_config(content)
    section = next(
        item
        for item in result.source_sections
        if item.path == "firewall shaping-profile"
    )
    assert section.status == ExtractionStatus.EXTRACT_ONLY
    assert section.object_count_source == 1
    assert section.object_count_parsed == 1
