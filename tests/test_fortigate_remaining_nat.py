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
  set protocol udp
  set start-port 5000
  set end-port 5001
  set snat enable
  set snat-ip 203.0.113.10
 next
end
"""
    parsed = parse_fortigate_config(config)
    assert parsed.multicast_policies[0].srcaddr == ["source-mcast"]
    rule = next(rule for rule in FGToIRTransformer(parsed).transform().nat_rules if rule.traffic_type == "multicast")
    assert rule.nat_family.value == "nat44"
    assert rule.original_source_ports[0].start == 5000
    assert rule.translated_sources == ["203.0.113.10"]
    assert not rule.requires_manual_review
