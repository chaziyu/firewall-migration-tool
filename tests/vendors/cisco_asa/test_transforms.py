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


def test_gateway_absent_routes_and_null0_distance_are_parsed_structurally():
    result = extract_cisco_asa_source(
        "route inside 192.0.2.0 255.255.255.0\n"
        "route null0 198.51.100.0 255.255.255.0 250\n"
    )
    absent, null_route = result.config.static_routes
    assert absent.gateway is None and absent.extraction_status == "PARTIAL"
    assert null_route.gateway is None and null_route.administrative_distance == 250


def test_vti_profile_without_a_definition_is_partial():
    result = extract_cisco_asa_source("interface Tunnel1\n tunnel source outside\n tunnel destination 203.0.113.5\n"
                                     " tunnel protection ipsec profile PROFILE\n")
    row = next(item for item in result.derived.vpn.topologies if item.topology_type == "vti")
    assert (row.tunnel_interface, row.tunnel_source, row.tunnel_destination) == ("Tunnel1", "outside", "203.0.113.5")
    assert (row.ipsec_profile, row.resolution_status) == ("PROFILE", "PARTIAL")


def test_vti_topology_follows_profile_and_exposes_selector_acl():
    result = extract_cisco_asa_source(
        "access-list SELECTOR extended permit ip any any\n"
        "crypto ipsec ikev1 transform-set TS esp-aes esp-sha-hmac\n"
        "crypto ipsec ikev2 ipsec-proposal P2\n protocol esp encryption aes-256\n"
        "crypto ca trustpoint TP\n enrollment self\n"
        "crypto ipsec profile VTI\n set ikev1 transform-set TS\n set ikev2 ipsec-proposal P2\n set trustpoint TP\n"
        "interface Tunnel1\n tunnel source outside\n tunnel destination 203.0.113.5\n"
        " tunnel protection ipsec profile VTI\n tunnel protection ipsec policy SELECTOR\n"
    )
    row = next(item for item in result.derived.vpn.ipsec_topologies if item.topology_type == "vti")
    assert row.transform_sets[0].name == "TS"
    assert row.ikev2_proposals[0].name == "P2"
    assert row.trustpoint.name == "TP"
    assert row.selector_acl == "SELECTOR"
    assert row.resolution_status == "RESOLVED"


def test_vti_resolved_profile_with_missing_selector_is_partial():
    result = extract_cisco_asa_source(
        "crypto ipsec ikev1 transform-set TS esp-aes esp-sha-hmac\n"
        "crypto ipsec profile VTI\n set ikev1 transform-set TS\n"
        "interface Tunnel1\n tunnel protection ipsec profile VTI\n"
        " tunnel protection ipsec policy MISSING\n"
    )
    row = next(item for item in result.derived.vpn.ipsec_topologies if item.topology_type == "vti")
    assert row.transform_sets[0].name == "TS"
    assert row.selector_acl is None
    assert row.resolution_status == "PARTIAL"
