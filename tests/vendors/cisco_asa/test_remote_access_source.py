from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def test_remote_access_source_is_explicit_and_context_scoped():
    config = CiscoASAParser("""changeto context blue
interface GigabitEthernet0/1
 nameif outside
webvpn
 enable outside
 tunnel-group-list enable
vpn-addr-assign aaa
vpn-addr-assign local reuse-delay 10
tunnel-group RA type remote-access
tunnel-group RA general-attributes
 default-group-policy GP
 authentication-server-group AUTH
tunnel-group RA webvpn-attributes
 authentication saml
changeto context green
webvpn
 enable outside
vpn-addr-assign dhcp
""").parse_raw()
    assert config.webvpn.enabled_interfaces == ["outside"]
    assert config.webvpn.source_context == "blue"
    assert config.vpn_address_assignment.aaa_enabled is True
    assert config.vpn_address_assignment.local_enabled is True
    assert config.vpn_address_assignment.reuse_delay == 10
    group = config.tunnel_groups[0]
    assert group.default_group_policy == "GP"
    assert group.general_attributes["authentication_server_group"] == "AUTH"
    assert group.webvpn_attributes["authentication"] == "saml"
    assert [item.source_context for item in config.webvpn_configs] == ["blue", "green"]
    assert [item.source_context for item in config.vpn_address_assignments] == ["blue", "green"]
    assert config.vpn_address_assignments[1].dhcp_enabled is True


def test_local_pool_uses_single_hyphenated_range_and_only_explicit_mask():
    config = CiscoASAParser(
        "ip local pool POOL 10.0.0.1-10.0.0.20\n"
        "ip local pool POOL2 10.1.0.10-10.1.0.30 mask 255.255.255.0\n"
    ).parse_raw()
    first, second = config.vpn_address_pools
    assert (first.start, first.end, first.mask) == ("10.0.0.1", "10.0.0.20", None)
    assert (second.start, second.end, second.mask) == ("10.1.0.10", "10.1.0.30", "255.255.255.0")


def test_local_pool_rejects_separate_addresses_instead_of_reinterpreting_them():
    config = CiscoASAParser("ip local pool POOL 10.0.0.1 10.0.0.20 mask 255.255.255.0\n").parse_raw()
    assert config.vpn_address_pools[0].extraction_status == "PARSE_ERROR"
