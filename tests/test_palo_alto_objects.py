from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import AddressType
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.parsers.palo_alto.resolver import PANResolver
from fwmigrate.parsers.palo_alto.source_model import PANScope, PANSourceObject
from tests.fixture_paths import PALO_ALTO_FIXTURE


OBJECTS_FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "objects.xml"


def _extract_objects():
    parser = PANOSSourceParser()
    extraction = parser.extract(OBJECTS_FIXTURE.read_text(encoding="utf-8"))
    return parser, extraction


def _address(extraction, name):
    return next(address for address in extraction.canonical_ir.addresses if address.name == name)


def _inventory(extraction, name):
    return [item for item in extraction.inventory_items if item.domain == "addresses" and item.name == name]


def test_ipv4_host_address_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "IPv4-Host")
    assert address.type == AddressType.HOST
    assert address.subnet == "10.10.10.50/32"
    assert address.address_family == "ipv4"
    assert address.is_ipv6 is False


def test_ipv4_network_address_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "IPv4-Net")
    assert address.type == AddressType.NETWORK
    assert address.subnet == "10.10.10.0/24"


def test_ipv6_host_address_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "IPv6-Host")
    assert address.type == AddressType.HOST
    assert address.subnet == "2001:db8::10/128"


def test_ipv6_network_address_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "IPv6-Net")
    assert address.type == AddressType.NETWORK
    assert address.subnet == "2001:db8:10::/64"


def test_ipv4_range_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "IPv4-Range")
    assert address.type == AddressType.RANGE
    assert address.ip_range_start == "192.0.2.10"
    assert address.ip_range_end == "192.0.2.20"
    assert address.address_family == "ipv4"


def test_ipv6_range_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "IPv6-Range")
    assert address.type == AddressType.RANGE
    assert address.ip_range_start == "2001:db8::10"
    assert address.ip_range_end == "2001:db8::20"
    assert address.address_family == "ipv6"


def test_ip_wildcard_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "Wildcard")
    assert address.type == AddressType.WILDCARD_MASK
    assert address.wildcard_mask == "10.5.1.1/0.127.248.2"
    assert address.source_type == "ip-wildcard"


def test_fqdn_extracted():
    _, extraction = _extract_objects()
    address = _address(extraction, "External-FQDN")
    assert address.type == AddressType.FQDN
    assert address.fqdn == "Api.Example.test"


def test_address_description_preserved():
    _, extraction = _extract_objects()
    assert _address(extraction, "Described").description == "Preserved description"


def test_address_tags_preserved():
    _, extraction = _extract_objects()
    assert _address(extraction, "Tagged").tags == ["production", "internet-facing"]


def test_ipv6_address_family_preserved():
    _, extraction = _extract_objects()
    for name in ("IPv6-Host", "IPv6-Net", "IPv6-Range"):
        address = _address(extraction, name)
        assert address.address_family == "ipv6"
        assert address.is_ipv6 is True
        assert address.source_attributes["pan_address_family"] == "ipv6"


def test_ip_wildcard_is_ipv4_only():
    _, extraction = _extract_objects()
    assert all(address.name != "IPv6-Wildcard" for address in extraction.canonical_ir.addresses)
    assert _inventory(extraction, "IPv6-Wildcard")[0].status == ExtractionStatus.PARSE_ERROR


def test_malformed_ip_netmask_not_added_to_ir():
    _, extraction = _extract_objects()
    assert all(address.name != "Bad-IP" for address in extraction.canonical_ir.addresses)


def test_malformed_ip_netmask_records_parse_error():
    _, extraction = _extract_objects()
    item = _inventory(extraction, "Bad-IP")[0]
    assert item.status == ExtractionStatus.PARSE_ERROR
    assert item.requires_manual_review is True
    assert item.source_attributes["pan_source_value"] == "not-an-ip/24"
    assert item.source_attributes["pan_description"] == "Invalid but retained"
    assert item.source_attributes["pan_tags"] == ["manual-review"]


def test_multiple_address_types_record_parse_error_without_canonical_object():
    _, extraction = _extract_objects()
    assert all(address.name != "Multiple-Types" for address in extraction.canonical_ir.addresses)
    item = _inventory(extraction, "Multiple-Types")[0]
    assert item.status == ExtractionStatus.PARSE_ERROR
    assert item.source_attributes["pan_configured_address_values"] == {
        "ip-netmask": "192.0.2.30/32",
        "fqdn": "duplicate.example.test",
    }


def test_missing_address_type_records_parse_error_without_canonical_object():
    _, extraction = _extract_objects()
    assert all(address.name != "Missing-Type" for address in extraction.canonical_ir.addresses)
    item = _inventory(extraction, "Missing-Type")[0]
    assert item.status == ExtractionStatus.PARSE_ERROR
    assert item.source_attributes["pan_description"] == "No address type"


def test_malformed_range_not_added_to_ir():
    _, extraction = _extract_objects()
    assert all(address.name != "Bad-Range" for address in extraction.canonical_ir.addresses)
    assert _inventory(extraction, "Bad-Range")[0].status == ExtractionStatus.PARSE_ERROR


def test_cross_family_range_records_parse_error():
    _, extraction = _extract_objects()
    assert all(address.name != "Cross-Family" for address in extraction.canonical_ir.addresses)
    assert _inventory(extraction, "Cross-Family")[0].status == ExtractionStatus.PARSE_ERROR


def test_malformed_wildcard_records_parse_error():
    _, extraction = _extract_objects()
    assert all(address.name != "Bad-Wildcard" for address in extraction.canonical_ir.addresses)
    assert _inventory(extraction, "Bad-Wildcard")[0].status == ExtractionStatus.PARSE_ERROR


def test_address_with_unknown_field_is_partial():
    _, extraction = _extract_objects()
    address = _address(extraction, "Has-Unknown")
    assert address.source_attributes["pan_unknown_fields"] == {"future-field": "retain-me"}
    assert _inventory(extraction, "Has-Unknown")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_valid_address_has_single_normalized_record():
    _, extraction = _extract_objects()
    records = _inventory(extraction, "IPv4-Host")
    assert len(records) == 1
    assert records[0].status == ExtractionStatus.NORMALIZED


def test_invalid_address_has_single_parse_error_record():
    _, extraction = _extract_objects()
    records = _inventory(extraction, "Bad-IP")
    assert len(records) == 1
    assert records[0].status == ExtractionStatus.PARSE_ERROR


def test_address_record_id_is_scope_stable():
    _, first = _extract_objects()
    _, second = _extract_objects()
    first_id = _inventory(first, "IPv4-Host")[0].source_record_id
    second_id = _inventory(second, "IPv4-Host")[0].source_record_id
    assert first_id == second_id
    assert "|vsys|vsys1|addresses|" in first_id


def test_reused_parser_does_not_leak_resolver_definitions_between_extractions():
    parser = PANOSSourceParser()
    content = OBJECTS_FIXTURE.read_text(encoding="utf-8")
    first = parser.extract(content)
    second = parser.extract(content)
    assert len(first.canonical_ir.addresses) == len(second.canonical_ir.addresses)
    assert _inventory(second, "IPv4-Host")[0].status == ExtractionStatus.NORMALIZED


def test_same_address_name_different_vsys_does_not_cross_resolve():
    parser, extraction = _extract_objects()
    first = parser.resolver.resolve("Scoped-Web", "address", PANScope(kind="vsys", name="vsys1"))
    second = parser.resolver.resolve("Scoped-Web", "address", PANScope(kind="vsys", name="vsys2"))
    assert first.ir_object.subnet == "10.1.0.1/32"
    assert second.ir_object.subnet == "10.2.0.1/32"
    assert first.ir_object in extraction.canonical_ir.addresses
    assert second.ir_object in extraction.canonical_ir.addresses


def test_shared_and_vsys_address_collision_gets_deterministic_canonical_names():
    _, extraction = _extract_objects()
    values_by_name = {address.subnet: address.name for address in extraction.canonical_ir.addresses}
    assert values_by_name["192.0.2.1/32"] == "Scoped-Web"
    assert values_by_name["10.1.0.1/32"] == "vsys1::Scoped-Web"
    assert values_by_name["10.2.0.1/32"] == "vsys2::Scoped-Web"


def test_invalid_address_is_not_registered_as_valid_canonical_object():
    parser, _ = _extract_objects()
    scope = PANScope(kind="vsys", name="vsys1")
    assert parser.resolver.resolve("Bad-IP", "address", scope) is None
    assert parser.resolver.resolve("Bad-IP", "address-reference", scope) is None


def test_address_and_group_storage_cannot_silently_overwrite():
    resolver = PANResolver()
    scope = PANScope(kind="vsys", name="vsys1")
    address = PANSourceObject(name="Web", kind="address", domain="address", source_path="address/Web", scope=scope)
    group = PANSourceObject(name="Web", kind="address-group", domain="address", source_path="address-group/Web", scope=scope)
    assert resolver.register_object(address, "address") is True
    assert resolver.register_object(group, "address-group") is True
    assert resolver.resolve("Web", "address", scope) is address
    assert resolver.resolve("Web", "address-group", scope) is group
    assert resolver.resolve("Web", "address-reference", scope) is None


def test_original_example_palo_addresses_still_extract():
    extraction = PANOSSourceParser().extract(PALO_ALTO_FIXTURE.read_text(encoding="utf-8"))
    by_name = {address.name: address for address in extraction.canonical_ir.addresses}
    assert by_name["Server_Web"].type == AddressType.HOST
    assert by_name["Server_Web"].subnet == "10.10.10.50/32"
    assert by_name["Net_LAN"].type == AddressType.NETWORK
    assert by_name["Net_LAN"].subnet == "10.10.0.0/16"
    assert by_name["Pool_DHCP"].ip_range_start == "192.168.1.100"
    assert by_name["Pool_DHCP"].ip_range_end == "192.168.1.200"
    assert by_name["FQDN_API"].type == AddressType.FQDN
    assert by_name["FQDN_API"].fqdn == "api.gateway.io"
