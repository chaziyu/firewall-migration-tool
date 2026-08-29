from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import AddressType
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_address_books_and_typed_addresses():
    fixture_path = JUNIPER_FIXTURES_DIR / "address_books.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    addr_dict = {a.name: a for a in ir.addresses}

    # IPv4 Host
    assert "host_ipv4" in addr_dict
    assert addr_dict["host_ipv4"].type == AddressType.HOST
    assert addr_dict["host_ipv4"].subnet == "10.0.0.10/32"

    # IPv6 Host
    assert "host_ipv6" in addr_dict
    assert addr_dict["host_ipv6"].type == AddressType.HOST
    assert addr_dict["host_ipv6"].subnet == "2001:db8::10/128"

    # Network
    assert "net_corp" in addr_dict
    assert addr_dict["net_corp"].type == AddressType.NETWORK
    assert addr_dict["net_corp"].subnet == "10.0.0.0/16"

    # FQDN
    assert "fqdn_portal" in addr_dict
    assert addr_dict["fqdn_portal"].type == AddressType.FQDN
    assert addr_dict["fqdn_portal"].fqdn == "portal.example.com"

    # Range
    assert "range_dhcp" in addr_dict
    assert addr_dict["range_dhcp"].type == AddressType.RANGE
    assert addr_dict["range_dhcp"].ip_range_start == "10.0.1.100"
    assert addr_dict["range_dhcp"].ip_range_end == "10.0.1.200"

    # Wildcard
    assert "wildcard_sub" in addr_dict
    assert addr_dict["wildcard_sub"].type == AddressType.WILDCARD_MASK
    assert addr_dict["wildcard_sub"].wildcard_mask == "10.0.0.0/0.0.255.255"

    # Description
    assert addr_dict["host_desc"].description == "Database primary"

    # Named book prefix
    assert "custom_dmz_book__dmz_server" in addr_dict

    assert_no_silent_loss(res, total_input_commands=21)

def test_malformed_range_address_no_silent_repair():
    content = """
    set version 21.4R1.12
    set system host-name SRX-BadRange
    set security address-book global address bad_range range-address 10.1.1.1
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    addr = next(a for a in ir.addresses if a.name == "bad_range")
    assert addr.requires_manual_review is True
    assert addr.migration_status == "PARTIALLY_NORMALIZED"
    assert addr.parse_error is not None

def test_resolver_scope_isolation():
    content = """
    set version 21.4R1.12
    set system host-name SRX-Scope
    set security zones security-zone dmz_zone address-book dmz_book
    set security address-book dmz_book address dmz_srv 10.20.1.10/32
    set security address-book internal_book address internal_srv 10.30.1.10/32
    set security policies from-zone dmz_zone to-zone dmz_zone policy P_Scope match source-address internal_srv
    set security policies from-zone dmz_zone to-zone dmz_zone policy P_Scope match destination-address dmz_srv
    set security policies from-zone dmz_zone to-zone dmz_zone policy P_Scope match application any
    set security policies from-zone dmz_zone to-zone dmz_zone policy P_Scope then permit
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    p = next(pol for pol in ir.policies if pol.name == "P_Scope")
    # internal_srv is not in dmz_book or global -> must be unresolved
    assert p.requires_manual_review is True
    assert any("Unresolved source address: internal_srv" in r for r in p.review_reasons)
