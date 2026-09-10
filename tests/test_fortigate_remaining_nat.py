from fwmigrate.parsers.fortigate.model import FGMulticastPolicy
from fwmigrate.ir.core import IRMulticastPolicy
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_ipv6_policy_pool_is_explicit_nat66():
    config = """
config firewall policy
 edit 1
  set srcintf lan
  set dstintf wan
  set srcaddr6 all
  set dstaddr6 all
  set service ALL
  set nat enable
  set ippool enable
  set poolname6 v6-pool
 next
end
config firewall ippool6
 edit v6-pool
  set startip 2001:db8::10
  set endip 2001:db8::20
 next
end
"""
    ir = FGToIRTransformer(parse_fortigate_config(config)).transform()
    rule = next(rule for rule in ir.nat_rules if rule.name == "SNAT6-P1")
    assert rule.nat_family.value == "nat66"
    assert rule.original_address_family == "ipv6"
    assert rule.translated_address_family == "ipv6"
    assert rule.translated_sources == ["2001:db8::10-2001:db8::20"]
    assert not rule.requires_manual_review


def test_multicast_nat_is_typed_and_auditable():
    config = """
config firewall multicast-policy
 edit 1
  set srcintf lan
  set dstintf wan
  set srcaddr source-mcast
  set dstaddr destination-mcast
  set protocol 17
  set start-port 5000
  set end-port 5001
  set snat enable
  set snat-ip 203.0.113.10
 next
end
"""
    parsed = parse_fortigate_config(config)
    assert parsed.multicast_policies[0].srcaddr == ["source-mcast"]
    assert parsed.multicast_policies[0].protocol == 17
    rule = next(rule for rule in FGToIRTransformer(parsed).transform().nat_rules if rule.traffic_type == "multicast")
    assert rule.nat_family.value == "nat44"
    assert rule.protocol_number == 17
    assert rule.protocol_name is None
    assert rule.source_from_interfaces == ["lan"]
    assert rule.source_to_interfaces == ["wan"]
    assert rule.original_source_ports == []
    assert rule.original_destination_ports[0].start == 5000
    assert rule.original_destination_ports[0].end == 5001
    assert rule.translated_sources == ["203.0.113.10"]
    assert rule.translated_destinations == []
    assert not rule.requires_manual_review


def test_multicast_dnat_only_maps_the_ipv4_destination():
    parsed = parse_fortigate_config(
        """config firewall multicast-policy
 edit 1
  set protocol 6
  set dnat 198.51.100.10
 next
end
"""
    )
    rule = FGToIRTransformer(parsed).transform().nat_rules[0]
    assert rule.type.value == "destination"
    assert rule.protocol_number == 6
    assert rule.translated_destinations == ["198.51.100.10"]
    assert rule.translated_sources == []
    assert not rule.requires_manual_review


def test_multicast_twice_nat_preserves_both_translations():
    parsed = parse_fortigate_config(
        """config firewall multicast-policy
 edit 1
  set snat enable
  set snat-ip 203.0.113.10
  set dnat 198.51.100.10
 next
end
"""
    )
    rule = FGToIRTransformer(parsed).transform().nat_rules[0]
    assert rule.type.value == "twice"
    assert rule.translated_sources == ["203.0.113.10"]
    assert rule.translated_destinations == ["198.51.100.10"]
    assert not rule.requires_manual_review


def test_multicast_policy_defaults_and_invalid_values_remain_auditable():
    defaults = parse_fortigate_config(
        """config firewall multicast-policy
 edit 1
 next
end
"""
    ).multicast_policies[0]
    assert defaults.protocol == 0
    assert defaults.action == "accept"
    assert defaults.dnat == "0.0.0.0"

    boundaries = FGMulticastPolicy(
        id=1, protocol="255", start_port="0", end_port="65535"
    )
    assert (boundaries.protocol, boundaries.start_port, boundaries.end_port) == (
        255, 0, 65535
    )

    invalid = FGMulticastPolicy(
        id=1,
        protocol="256",
        start_port="-1",
        end_port="65536",
        dnat="enable",
    )
    assert invalid.protocol is None
    assert invalid.start_port is None
    assert invalid.end_port is None
    assert invalid.dnat is None
    assert {
        "unparsed_protocol",
        "unparsed_start_port",
        "unparsed_end_port",
        "unparsed_dnat",
    } <= invalid.extra_settings.keys()


def test_multicast_interfaces_are_scalars_and_addresses_remain_lists():
    parsed = parse_fortigate_config(
        """config firewall multicast-policy
 edit 1
  set srcintf lan
  set dstintf wan
  set srcaddr source-a source-b
  set dstaddr group-a group-b
 next
 edit 2
 next
end
"""
    )

    first, second = parsed.multicast_policies
    assert first.srcintf == "lan"
    assert first.dstintf == "wan"
    assert first.srcaddr == ["source-a", "source-b"]
    assert first.dstaddr == ["group-a", "group-b"]
    assert second.srcintf is None
    assert second.dstintf is None


def test_multicast_policy_ir_is_separate_from_ipv4_nat_derivation():
    parsed = parse_fortigate_config(
        """config firewall multicast-policy
 edit 1
  set srcintf lan
  set dstintf wan
  set srcaddr source-mcast
  set dstaddr destination-mcast
 next
end
config firewall multicast-policy6
 edit 2
  set srcintf lan6
  set dstintf wan6
  set srcaddr source6
  set dstaddr destination6
 next
end
"""
    )
    ir = FGToIRTransformer(parsed).transform()

    assert [(item.source_id, item.address_family) for item in ir.multicast_policies] == [
        (1, "ipv4"), (2, "ipv6")
    ]
    assert ir.multicast_policies[0].source_interface == "lan"
    assert ir.multicast_policies[1].destination_addresses == ["destination6"]
    assert ir.nat_rules == []


def test_multicast_typed_fields_leave_unknown_settings_in_extra_settings():
    parsed = parse_fortigate_config(
        """config firewall multicast-policy
 edit 1
  set comments "review this"
  set ips-sensor ips1
  set logtraffic enable
  set utm-status enable
  set traffic-shaper shaper1
  set auto-asic-offload disable
  set future-setting retain-me
 next
end
"""
    )
    source = parsed.multicast_policies[0]
    assert source.comments == "review this"
    assert source.ips_sensor == "ips1"
    assert source.logtraffic == "enable"
    assert source.utm_status == "enable"
    assert source.traffic_shaper == "shaper1"
    assert source.auto_asic_offload == "disable"
    assert source.extra_settings == {"future_setting": "retain-me"}

    policy = FGToIRTransformer(parsed).transform().multicast_policies[0]
    assert policy.traffic_shaper == "shaper1"
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True


def test_multicast_ipv6_keeps_ipv4_only_fields_source_only_without_nat():
    parsed = parse_fortigate_config(
        """config firewall multicast-policy6
 edit 1
  set snat enable
  set dnat 2001:db8::10
  set traffic-shaper v6-shaper
 next
end
"""
    )
    source = parsed.multicast_policies6[0]
    assert source.snat is None
    assert source.dnat == "0.0.0.0"
    assert source.traffic_shaper is None
    assert source.extra_settings == {
        "snat": "enable",
        "dnat": "2001:db8::10",
        "traffic_shaper": "v6-shaper",
    }

    ir = FGToIRTransformer(parsed).transform()
    assert ir.multicast_policies[0].address_family == "ipv6"
    assert ir.multicast_policies[0].source_attributes == source.extra_settings
    assert ir.nat_rules == []


def test_multicast_coverage_counts_policy_ir_and_dependencies_by_family():
    result = extract_fortigate_config(
        """config system interface
 edit lan
 next
 edit wan
 next
end
config firewall address
 edit source-a
 next
end
config firewall multicast-address
 edit group-a
 next
end
config firewall multicast-policy
 edit 1
  set srcintf lan
  set dstintf wan
  set srcaddr source-a
  set dstaddr group-a
 next
end
"""
    )
    section = next(item for item in result.source_sections if item.path == "firewall multicast-policy")
    assert section.status == ExtractionStatus.NORMALIZED
    assert section.object_count_parsed == 1
    assert section.object_count_normalized == 1
    assert {item.source_field for item in result.dependencies} == {
        "srcintf", "dstintf", "srcaddr", "dstaddr"
    }
    assert all(item.result == "RESOLVED" for item in result.dependencies)


def test_multicast_dependency_rules_resolve_typed_ips_and_shaper_references():
    result = extract_fortigate_config(
        """config system interface
 edit lan
 next
 edit wan
 next
end
config firewall address
 edit source-a
 next
end
config firewall multicast-address
 edit group-a
 next
end
config ips sensor
 edit ips-a
 next
end
config firewall shaper traffic-shaper
 edit shaper-a
 next
end
config firewall multicast-policy
 edit 1
  set srcintf lan
  set dstintf wan
  set srcaddr source-a
  set dstaddr group-a
  set ips-sensor ips-a
  set traffic-shaper shaper-a
 next
end
"""
    )
    dependencies = {
        item.source_field: item
        for item in result.dependencies
    }
    assert dependencies["ips-sensor"].target_path == "ips sensor"
    assert dependencies["traffic-shaper"].target_path == "firewall shaper traffic-shaper"
    assert result.generation_safe is False


def test_multicast_dependency_rules_fail_closed_for_missing_family_objects():
    result = extract_fortigate_config(
        """config firewall address
 edit shared
 next
end
config firewall multicast-policy6
 edit 1
  set srcaddr shared
  set dstaddr missing6
 next
end
"""
    )
    dependencies = {
        item.source_field: item
        for item in result.dependencies
    }
    assert dependencies["srcaddr"].result == "UNRESOLVED"
    assert dependencies["srcaddr"].expected_type == "firewall address6"
    assert dependencies["dstaddr"].result == "UNRESOLVED"
    assert dependencies["dstaddr"].expected_type == "firewall multicast-address6"
    assert result.generation_safe is False


def test_multicast_dependency_rules_stay_scoped_to_each_vdom():
    result = extract_fortigate_config(
        """config vdom
 edit tenant-a
  config system interface
   edit lan
   next
  end
  config firewall address
   edit source
   next
  end
  config firewall multicast-address
   edit group
   next
  end
  config firewall multicast-policy
   edit 1
    set srcintf lan
    set srcaddr source
    set dstaddr group
   next
  end
 next
 edit tenant-b
  config system interface
   edit lan
   next
  end
  config firewall address
   edit source
   next
  end
  config firewall multicast-address
   edit group
   next
  end
  config firewall multicast-policy
   edit 1
    set srcintf lan
    set srcaddr source
    set dstaddr group
   next
  end
 next
end
"""
    )
    multicast_dependencies = [
        item for item in result.dependencies
        if item.source_path == "firewall multicast-policy"
    ]
    assert len(multicast_dependencies) == 6
    assert {item.source_context for item in multicast_dependencies} == {
        "tenant-a", "tenant-b"
    }
    assert all(item.result == "RESOLVED" for item in multicast_dependencies)


def test_multicast_ir_model_serializes_all_policy_fields():
    policy = IRMulticastPolicy(
        source_id=1,
        address_family="ipv6",
        source_interface="lan6",
        destination_interface="wan6",
        source_addresses=["source6"],
        destination_addresses=["group6"],
        protocol_number=17,
        destination_port_start=5000,
        destination_port_end=5001,
        auto_asic_offload="disable",
    )
    serialized = policy.model_dump()
    assert serialized["address_family"] == "ipv6"
    assert serialized["source_addresses"] == ["source6"]
    assert serialized["destination_port_end"] == 5001
    assert serialized["auto_asic_offload"] == "disable"
