from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_ipv6_route_normalizes_prefix_and_preserves_tunneled():
    parser = CiscoASAParser("ipv6 route outside 2001:db8::/64 2001:db8::1 5 tunneled")
    ir = parser.transform_to_ir()
    source = parser.config.static_routes[0]
    assert source.address_family == "ipv6"
    assert source.tunneled and source.administrative_distance == 5
    assert ir.routes[0].destination == "2001:db8::/64"
    assert ir.routes[0].address_family == "ipv6"
    assert ir.routes[0].source_attributes["tunneled"] is True
    assert ir.routes[0].requires_manual_review


def test_ipv4_route_track_and_tunneled_are_not_silently_ignored():
    parser = CiscoASAParser("""
route outside 0.0.0.0 0.0.0.0 192.0.2.1 1 track 7
route outside 10.0.0.0 255.255.255.0 192.0.2.2 tunneled
""")
    ir = parser.transform_to_ir()
    assert parser.config.static_routes[0].track_id == 7
    assert parser.config.static_routes[1].tunneled
    assert ir.routes[0].source_attributes["track_id"] == 7
    assert ir.routes[1].source_attributes["tunneled"] is True
    assert all(item.requires_manual_review for item in ir.routes)


def test_unknown_route_tail_is_preserved_and_requires_review():
    parser = CiscoASAParser("route outside 10.0.0.0 255.255.255.0 192.0.2.1 mystery")
    ir = parser.transform_to_ir()
    assert parser.config.static_routes[0].raw_options == ["mystery"]
    assert ir.routes[0].requires_manual_review


def test_route_variants_preserve_order_distance_and_named_tracking():
    parser = CiscoASAParser("""
route outside 10.0.0.0 255.255.255.0 192.0.2.1 20
route outside 10.0.0.0 255.255.255.0 192.0.2.2 5 track 42
route outside 0.0.0.0 0.0.0.0 192.0.2.254
""")
    config = parser.parse_raw()
    assert [(r.destination, r.gateway, r.administrative_distance, r.effective_administrative_distance, r.track_id) for r in config.static_routes] == [
        ("10.0.0.0", "192.0.2.1", 20, 20, None),
        ("10.0.0.0", "192.0.2.2", 5, 5, 42),
        ("0.0.0.0", "192.0.2.254", None, 1, None),
    ]


def test_track_and_sla_are_structured_and_linked():
    config = CiscoASAParser("""
interface outside
sla monitor 1
 frequency 10
track 7 rtr 1 reachability
route outside 0.0.0.0 0.0.0.0 192.0.2.1 track 7
""").parse_raw()
    assert config.tracks[0].sla_id == 1
    assert config.sla_monitors[0].frequency == 10
    assert not [issue for issue in config.reference_issues if not issue["resolved"]]


def test_route_map_order_acl_and_actions_are_structured_without_acl_policy():
    parser = CiscoASAParser("""
route-map PBR permit 20
 match access-list PBR-ACL
 set ip next-hop 192.0.2.1
route-map PBR deny 30
 set interface outside
interface inside
 policy-route route-map PBR
""")
    config = parser.parse_raw()
    assert [(r.sequence, r.action) for r in config.route_maps[0].rules] == [(20, "permit"), (30, "deny")]
    assert config.route_maps[0].rules[0].match_acl == "PBR-ACL"
    assert config.route_maps[0].rules[0].set_next_hop == "192.0.2.1"
    assert config.route_maps[0].rules[1].set_interface == "outside"
    assert config.interfaces[0].policy_route_maps == ["PBR"]
    assert not config.access_rules


def test_official_pbr_syntax_reaches_canonical_policy_routes_without_static_route():
    ir = CiscoASAParser("""
access-list PBR-ACL extended permit ip any any
route-map PBR permit 10
 match ip address PBR-ACL
 set ip next-hop 192.0.2.1
interface inside
 policy-route route-map PBR
""").transform_to_ir()
    assert len(ir.policy_route_rules) == 1
    rule = ir.policy_route_rules[0]
    assert (rule.source_order, rule.match_acl, rule.ingress_interface, rule.next_hop) == (
        10, "PBR-ACL", "inside", "192.0.2.1"
    )
    assert not ir.routes


def test_pbr_verify_availability_preserves_all_next_hops():
    config = CiscoASAParser("""
route-map PBR permit 10
 set ip next-hop verify-availability 192.0.2.1 192.0.2.2
""").parse_raw()
    rule = config.route_maps[0].rules[0]
    assert rule.set_next_hop == "192.0.2.1"
    assert rule.source_attributes["next_hops"] == ["192.0.2.1", "192.0.2.2"]
    assert rule.next_hops == ["192.0.2.1", "192.0.2.2"]


def test_pbr_preserves_multiple_acls_interfaces_and_match_evidence():
    ir = CiscoASAParser("""
access-list PBR-ONE extended permit tcp 10.0.0.0 255.255.255.0 any eq 443
access-list PBR-TWO extended deny udp any host 192.0.2.10 range 1000 1001
route-map PBR permit 10
 match ip address PBR-ONE PBR-TWO
 set ip next-hop 192.0.2.1 192.0.2.2
 set interface inside outside
interface GigabitEthernet0/0
 policy-route route-map PBR
""").transform_to_ir()
    rule = ir.policy_route_rules[0]
    assert rule.match_acls == ["PBR-ONE", "PBR-TWO"]
    assert rule.next_hops == ["192.0.2.1", "192.0.2.2"]
    assert rule.output_interfaces == ["inside", "outside"]
    assert [item["destination_port"] for item in rule.match_evidence] == ["eq 443", "range 1000 1001"]
    assert not ir.routes


def test_malformed_route_is_parse_error_and_unknown_dynamic_command_is_preserved():
    parser = CiscoASAParser("""
route outside 10.0.0.0 255.0.255.0 192.0.2.1
router ospf 1
""")
    config = parser.parse_raw()
    assert config.static_routes[0].migration_status == "PARSE_ERROR"
    assert config.static_routes[0].raw_line.startswith("route outside")
    assert config.dynamic_routing[0].source_attributes["protocol"] == "ospf"
