from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input


def test_gaia_cli_is_extracted_by_the_gaia_front_end():
    bundle, _ = load_checkpoint_input(
        "set interface eth0 ipv4-address 192.0.2.1 mask-length 24\n"
        "set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.254 on\n"
    )
    config = extract_checkpoint_config(bundle).config

    assert [item.object_type for item in config.gaia_interfaces] == ["interface"]
    assert [item.object_type for item in config.gaia_static_routes] == ["static-route"]
    assert all(item.source_plane == "gaia" for item in config.gaia_interfaces + config.gaia_static_routes)
