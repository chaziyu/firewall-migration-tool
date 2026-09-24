from copy import deepcopy

from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source


def test_object_nat_order_and_source_immutability():
    result = extract_cisco_asa_source(
        "object network B\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n"
        "object network A\n host 10.0.0.2\n nat (inside,outside) static 192.0.2.2\n"
        "nat (inside,outside) source static 10.0.0.1 192.0.2.1\n")
    before = deepcopy(result.config)
    by_name = {row.ordering_inputs.object_name: row for row in result.derived.nat.rules if row.section == "object"}
    assert (by_name["A"].effective_order, by_name["B"].effective_order) == (2, 3)
    assert by_name["A"].translation_semantics == "static"
    assert result.config == before


def test_route_transform_separates_configured_and_effective_values():
    result = extract_cisco_asa_source("route outside 192.0.2.0 255.255.255.0 192.0.2.1\n"
                                     "ipv6 route outside 2001:db8::1/64 2001:db8::2 10\n")
    ipv4, ipv6 = result.derived.routes.routes
    assert (ipv4.configured_administrative_distance, ipv4.effective_administrative_distance) == (None, 1)
    assert ipv4.normalized_destination == "192.0.2.0/24"
    assert (ipv6.configured_administrative_distance, ipv6.effective_administrative_distance) == (10, 10)
    assert ipv6.normalized_destination == "2001:db8::/64"
    assert ipv6.source_route.destination == "2001:db8::1/64"


def test_vti_profile_remains_source_only():
    result = extract_cisco_asa_source("interface Tunnel1\n tunnel source outside\n tunnel destination 203.0.113.5\n"
                                     " tunnel protection ipsec profile PROFILE\n")
    row = next(item for item in result.derived.vpn.topologies if item.topology_type == "vti")
    assert (row.tunnel_interface, row.tunnel_source, row.tunnel_destination) == ("Tunnel1", "outside", "203.0.113.5")
    assert (row.ipsec_profile, row.resolution_status) == ("PROFILE", "SOURCE_ONLY")
