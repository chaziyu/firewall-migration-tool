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
    assert [(r.destination, r.gateway, r.administrative_distance, r.track_id) for r in config.static_routes] == [
        ("10.0.0.0", "192.0.2.1", 20, None),
        ("10.0.0.0", "192.0.2.2", 5, 42),
        ("0.0.0.0", "192.0.2.254", None, None),
    ]


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


def test_malformed_route_is_parse_error_and_unknown_dynamic_command_is_preserved():
    parser = CiscoASAParser("""
route outside 10.0.0.0 255.0.255.0 192.0.2.1
router ospf 1
""")
    config = parser.parse_raw()
    assert config.static_routes[0].migration_status == "PARSE_ERROR"
    assert config.static_routes[0].raw_line.startswith("route outside")
    assert config.unsupported_commands[0]["raw_line"] == "router ospf 1"
