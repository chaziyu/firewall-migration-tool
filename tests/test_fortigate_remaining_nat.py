from fwmigrate.parsers.fortigate.model import FGMulticastPolicy
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
