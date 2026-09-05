from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def parse(text):
    return CiscoASAParser(text).parse_raw()


def test_forward_and_nested_network_references_resolve():
    config = parse("""
object-group network OUTER
 group-object INNER
object-group network INNER
 network-object object HOST
object network HOST
 host 10.0.0.1
""")
    assert not [issue for issue in config.reference_issues if not issue["resolved"]]


def test_missing_network_reference_is_partial():
    config = parse("""
object-group network G
 network-object object MISSING
""")
    assert config.network_groups[0].requires_manual_review
    assert any(not issue["resolved"] for issue in config.reference_issues)


def test_missing_service_and_time_range_references_are_reported():
    config = parse("""
object-group service WEB tcp
 service-object object MISSING_SERVICE
access-list OUT extended permit tcp any any eq 443 time-range MISSING_TIME
""")
    missing = {issue["reference_name"] for issue in config.reference_issues if not issue["resolved"]}
    assert {"MISSING_SERVICE", "MISSING_TIME"} <= missing


def test_route_map_crypto_group_policy_and_interface_references_are_reported():
    config = parse("""
interface GigabitEthernet0/1
 nameif outside
 ip address 192.0.2.1 255.255.255.0
route-map PBR permit 10
 match access-list MISSING_ACL
crypto map OUTSIDE 10 match address MISSING_CRYPTO_ACL
tunnel-group peer.example type ipsec-l2l
 default-group-policy MISSING_POLICY
""")
    missing = {issue["reference_name"] for issue in config.reference_issues if not issue["resolved"]}
    assert {"MISSING_ACL", "MISSING_CRYPTO_ACL", "MISSING_POLICY"} <= missing


def test_network_and_service_cycles_are_reported_without_recursion_error():
    config = parse("""
object-group network A
 group-object B
object-group network B
 group-object A
object-group service SA tcp
 group-object SB
object-group service SB tcp
 group-object SA
""")
    reasons = [issue["reason"] for issue in config.reference_issues]
    assert any("A -> B -> A" in reason for reason in reasons)
    assert any("SA -> SB -> SA" in reason for reason in reasons)
