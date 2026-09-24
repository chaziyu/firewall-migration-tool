from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input


def test_gaia_commands_remain_gaia_source_records():
    bundle, _ = load_checkpoint_input("set interface eth0 ipv4-address 192.0.2.1 mask-length 24\nset static-route 10.0.0.0/8 nexthop gateway address 192.0.2.254 on\n")
    config = extract_checkpoint_config(bundle).config
    assert config.gaia_interfaces and config.gaia_static_routes
    assert all(item.source_plane == "gaia" for item in config.gaia_interfaces + config.gaia_static_routes)


def test_gaia_route_does_not_infer_fields_not_present_in_source():
    bundle, _ = load_checkpoint_input(
        "set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.254 on\n"
    )

    route = extract_checkpoint_config(bundle).config.gaia_static_routes[0]

    assert route.address_family == "ipv4"
    assert route.ipv4_destination == "10.0.0.0/8"
    assert route.ipv6_destination is None
    assert route.next_hops[0].next_hop_type == "gateway"
    assert route.next_hops[0].gateway == "192.0.2.254"
