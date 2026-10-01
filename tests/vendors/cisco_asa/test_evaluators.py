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

def test_ntp_authentication_commands_are_structured_without_secret_material():
    parser = CiscoASAParser(
        "ntp authenticate\n"
        "ntp trusted-key 7\n"
        "ntp authentication-key 7 md5 NTP_SECRET_SENTINEL\n"
        "ntp server 192.0.2.123 key 7\n"
    )
    config = parser.parse_raw()

    settings = {item.setting: item for item in config.management_settings if item.setting}
    assert settings["ntp authenticate"].enabled is True
    assert settings["ntp trusted-key 7"].enabled is True
    key = settings["ntp authentication-key 7 md5"]
    assert key.enabled is True
    assert key.source_attributes["secret_present"] is True
    assert "NTP_SECRET_SENTINEL" not in str(key.model_dump())
    assert config.ntp_servers[0].key_id == "7"


def test_ipv6_ssh_management_source_is_valid_and_preserved():
    config = CiscoASAParser("ssh 2001:db8:1::/64 outside\n").parse_raw()

    rule = config.management_access_rules[0]
    assert rule.address_family == "ipv6"
    assert rule.source == "2001:db8:1::/64"
    assert rule.mask_or_prefix is None
    assert rule.interface == "outside"
    assert rule.extraction_status != "PARSE_ERROR"
    assert not config.diagnostics

