from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def test_management_and_routing_evaluators_construct_native_records():
    parser = CiscoASAParser("")
    parser._parse_management_command("hostname edge", 1)
    route, error = parser._parse_route_line("route outside 0.0.0.0 0.0.0.0 192.0.2.1")
    assert parser.config.system_settings.hostname == "edge"
    assert error is None
    assert route.interface == "outside" and route.gateway == "192.0.2.1"


def test_nat_and_vpn_evaluators_keep_source_order_and_explicit_fields():
    parser = CiscoASAParser("")
    parser._parse_nat_line("nat (inside,outside) source static WEB interface", 7)
    parser._parse_crypto_map_line("crypto map VPN 10 match address CRYPTO", 8)
    assert parser.config.nat_rules[0].source_order == 7
    assert parser.config.crypto_maps[0].sequence == 10
    assert "sequence" in parser.config.crypto_maps[0].explicit_fields
