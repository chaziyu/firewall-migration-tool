from fwmigrate.conversion.palo_alto_to_cisco_asa.planning.egress_zone import RouteZone, prove_egress_zone


def test_proves_complete_single_zone_using_longest_prefix_routes():
    routes = (RouteZone("10.0.0.0/8", "inside"), RouteZone("10.1.0.0/16", "dmz"))
    assert prove_egress_zone("10.1.2.0/24", routes, routing_complete=True) == "dmz"
    assert prove_egress_zone("10.2.0.0/16", routes, routing_complete=True) == "inside"


def test_rejects_destination_space_with_multiple_egress_zones_or_uncovered_addresses():
    routes = (RouteZone("10.0.0.0/24", "inside"), RouteZone("10.0.1.0/24", "dmz"))
    assert prove_egress_zone("10.0.0.0/23", routes, routing_complete=True) is None
    assert prove_egress_zone("10.0.0.0/23", routes[:1], routing_complete=True) is None


def test_rejects_incomplete_ambiguous_or_unbounded_route_evidence():
    assert prove_egress_zone("10.0.0.0/24", (RouteZone("0.0.0.0/0", "outside"),), routing_complete=False) is None
    assert prove_egress_zone("10.0.0.0/24", (RouteZone("10.0.0.0/24", "a"), RouteZone("10.0.0.0/24", "b")), routing_complete=True) is None
    assert prove_egress_zone("10.0.0.0/24", (RouteZone("0.0.0.0/0", "outside"),), routing_complete=True, segment_limit=0) is None
    assert prove_egress_zone("invalid", (), routing_complete=True) is None


def test_more_specific_routes_can_split_a_destination_and_fail_proof():
    routes = (RouteZone("10.0.0.0/24", "inside"), RouteZone("10.0.0.128/25", "dmz"))
    assert prove_egress_zone("10.0.0.0/24", routes, routing_complete=True) is None
