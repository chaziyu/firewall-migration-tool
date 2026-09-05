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


def test_vpn_crypto_map_aggregation_and_semantics():
    config = parse("""
access-list VPN extended permit ip any any
crypto ipsec ikev1 transform-set TS esp-aes esp-sha-hmac
crypto map OUTSIDE 10 match address VPN
crypto map OUTSIDE 10 set peer 203.0.113.1
crypto map OUTSIDE 10 set transform-set TS
crypto map OUTSIDE 10 set pfs group14
crypto map OUTSIDE 10 set security-association lifetime seconds 3600
""")
    assert len(config.crypto_maps) == 1
    item = config.crypto_maps[0]
    assert item.acl_name == "VPN"
    assert item.peer == "203.0.113.1"
    assert item.transform_sets == ["TS"]
    assert item.pfs_group == "group14"
    assert item.security_association_lifetime_seconds == 3600
    assert not [issue for issue in config.reference_issues if not issue["resolved"]]


def test_vpn_psk_is_presence_only():
    config = parse("""
tunnel-group peer.example type ipsec-l2l
 ipsec-attributes
  pre-shared-key synthetic-secret
""")
    item = config.tunnel_groups[0]
    assert item.ikev1_psk_present
    assert "synthetic-secret" not in str(config.model_dump())


def test_route_tracking_reference_is_validated():
    config = parse("""
track 7 rtr 1 reachability
route outside 0.0.0.0 0.0.0.0 192.0.2.1 1 track 7
route outside 10.0.0.0 255.255.255.0 192.0.2.2 1 track 8
""")
    missing = [issue for issue in config.reference_issues if issue["reference_name"] == "8"]
    assert not [issue for issue in config.reference_issues if issue["reference_name"] == "7" and not issue["resolved"]]
    assert missing and not missing[0]["resolved"]
    assert config.static_routes[1].requires_manual_review


def test_service_members_keep_types_ports_and_nested_references():
    config = parse("""
object service HTTP
 service tcp source eq WEB_SRC destination eq WEB_DST
object-group service INNER tcp
 service-object object HTTP
object-group service OUTER tcp
 group-object INNER
 port-object range 8000 8010
object-group protocol P_INNER
 protocol-object tcp
object-group protocol P_OUTER
 group-object P_INNER
object-group icmp-type I_INNER
 icmp-object echo
object-group icmp-type I_OUTER
 group-object I_INNER
""")
    service = config.service_objects[0].ports[0]
    assert service.source.values == ["WEB_SRC"]
    assert service.destination.values == ["WEB_DST"]
    assert config.service_groups[1].member_entries[0].type == "service_group"
    assert config.service_groups[1].member_entries[1].type == "port_object"
    assert config.protocol_groups[1].member_entries[0].type == "protocol_group"
    assert config.icmp_type_groups[1].member_entries[0].type == "icmp_group"
    assert not [issue for issue in config.reference_issues if not issue["resolved"]]


def test_named_ports_are_preserved_without_iana_guessing():
    ir = CiscoASAParser("""
object service LOCAL
 service tcp source eq LOCAL_SRC destination eq LOCAL_DST
access-list A extended permit tcp any any object LOCAL
""").transform_to_ir()
    service = next(item for item in ir.services if item.name == "LOCAL")
    assert service.ports[0].source_port == "LOCAL_SRC"
    assert service.ports[0].port == "LOCAL_DST"


def test_icmp_group_cycle_and_named_types_are_reported():
    config = parse("""
object-group icmp-type A
 group-object B
object-group icmp-type B
 group-object A
access-list A extended permit icmp6 any any nd-na
""")
    assert any("A -> B -> A" in issue["reason"] for issue in config.reference_issues)
    assert config.access_rules[0].protocol == "icmp6"
    assert config.access_rules[0].icmp_type == "nd-na"


def test_multiple_time_range_clauses_are_all_normalized_and_referenced():
    ir = CiscoASAParser("""
time-range MIXED
 absolute start 00:00 1 January 2025 end 23:59 2 January 2025
 absolute start 00:00 3 February 2025 end 23:59 4 February 2025
 periodic weekdays 09:00 to 17:00
 periodic weekend 10:00 to 12:00
access-list A extended permit ip any any time-range MIXED
access-group A in interface inside
""").transform_to_ir()
    schedule = ir.schedules[0]
    assert len(schedule.windows) == 4
    assert {window["type"] for window in schedule.windows} == {"absolute", "periodic"}
    assert schedule.windows[2]["days"] == ["weekdays"]
    assert ir.policies[0].schedule == "MIXED"


def test_missing_and_malformed_time_ranges_remain_visible():
    config = parse("""
time-range BROKEN
 periodic daily 25:00 to 06:00
access-list A extended permit ip any any time-range BROKEN
access-list A extended permit ip any any time-range MISSING
""")
    names = {issue["reference_name"] for issue in config.reference_issues if not issue["resolved"]}
    assert "MISSING" in names
    assert config.time_ranges[0].migration_status == "PARSE_ERROR"
