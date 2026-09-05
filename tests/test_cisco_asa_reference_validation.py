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


def test_malformed_existing_time_range_is_resolved_but_invalid():
    config = parse("""
time-range BROKEN
 periodic daily 25:00 to 06:00
access-list OUT extended permit ip any any time-range BROKEN
""")
    issue = next(issue for issue in config.reference_issues if issue["reference_name"] == "BROKEN" and "parse errors" in issue["reason"])
    assert issue["resolved"] is True
    assert config.access_rules[0].migration_status == "PARTIALLY_NORMALIZED"
    assert config.access_rules[0].requires_manual_review is True


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


def test_typed_service_cycle_marks_only_cycle_members():
    config = parse("""
object-group service A tcp
 group-object B
object-group service B tcp
 group-object A
object-group service SAFE tcp
 port-object eq 443
""")
    groups = {group.name: group for group in config.service_groups}
    assert all(groups[name].requires_manual_review for name in ("A", "B"))
    assert not groups["SAFE"].requires_manual_review
    assert any("A -> B -> A" in issue["reason"] for issue in config.reference_issues)


def test_network_group_family_propagates_through_nested_and_mixed_members():
    config = parse("""
object network HOST4
 host 10.0.0.1
object network HOST6
 host 2001:db8::1
object-group network V4
 network-object object HOST4
object-group network V4_OUTER
 group-object V4
object-group network V6
 network-object object HOST6
object-group network MIXED
 group-object V4
 group-object V6
object-group network UNKNOWN
 group-object MISSING
""")
    groups = {group.name: group for group in config.network_groups}
    assert groups["V4"].address_family == "ipv4"
    assert groups["V4_OUTER"].address_family == "ipv4"
    assert groups["V6"].address_family == "ipv6"
    assert groups["MIXED"].address_family == "mixed"
    assert groups["UNKNOWN"].address_family is None
    assert groups["UNKNOWN"].migration_status == "PARTIALLY_NORMALIZED"
    assert groups["UNKNOWN"].requires_manual_review
    assert "Unresolved network group reference: MISSING" in groups["UNKNOWN"].review_reasons


def test_cycle_marks_every_participant_but_not_unrelated_groups():
    config = parse("""
object-group network A
 group-object B
object-group network B
 group-object C
object-group network C
 group-object A
object-group network SAFE
 network-object host 192.0.2.1
""")
    groups = {group.name: group for group in config.network_groups}
    assert all(groups[name].requires_manual_review for name in ("A", "B", "C"))
    assert not groups["SAFE"].requires_manual_review
    assert any("A -> B -> C -> A" in issue["reason"] for issue in config.reference_issues)
