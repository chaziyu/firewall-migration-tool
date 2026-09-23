from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input


def test_gaia_commands_remain_gaia_source_records():
    bundle, _ = load_checkpoint_input("set interface eth0 ipv4-address 192.0.2.1 mask-length 24\nset static-route 10.0.0.0/8 nexthop gateway address 192.0.2.254 on\n")
    config = extract_checkpoint_config(bundle).config
    assert config.gaia_interfaces and config.gaia_routes
    assert all(item.source_plane == "gaia" for item in config.gaia_interfaces + config.gaia_routes)
