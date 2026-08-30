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
