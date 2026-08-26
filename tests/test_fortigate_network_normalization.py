import pytest

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.net_utils import (
    normalize_ipv4_network,
    normalize_ipv4_prefix,
)
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _transform(config: str):
    return FGToIRTransformer(parse_fortigate_config(config)).transform()


def test_strict_ipv4_normalization_accepts_valid_prefixes_and_networks():
    assert normalize_ipv4_prefix(
        "192.168.1.10 255.255.255.0"
    ) == "192.168.1.10/24"
    assert normalize_ipv4_prefix("192.168.1.10/24") == "192.168.1.10/24"
    assert normalize_ipv4_network(
        "192.168.1.15 255.255.255.0"
    ) == "192.168.1.0/24"
    assert normalize_ipv4_network("192.168.1.15/24") == "192.168.1.0/24"
    assert normalize_ipv4_network(
        "0.0.0.0 0.0.0.0"
    ) == "0.0.0.0/0"


@pytest.mark.parametrize(
    "mask",
    ["255.0.255.0", "255.255.999.0", "255.255.255", "abc", "255.255.255.1"],
)
def test_strict_ipv4_normalization_rejects_malformed_masks(mask):
    with pytest.raises(ValueError):
        normalize_ipv4_prefix(f"10.0.0.1 {mask}")
    with pytest.raises(ValueError):
        normalize_ipv4_network(f"10.0.0.1 {mask}")


def test_omitted_static_route_destination_retains_default_semantics():
    ir = _transform("""
config router static
    edit 1
        set gateway 192.0.2.1
        set device "wan1"
    next
end
""")

    route = ir.routes[0]
    assert route.destination == "0.0.0.0/0"
    assert route.source_destination == "0.0.0.0 0.0.0.0"
    assert route.parse_error is None
    assert route.requires_manual_review is False


def test_invalid_static_route_is_preserved_without_default_fallback():
    ir = _transform("""
config router static
    edit 20
        set dst 10.20.30.0 255.0.255.0
        set gateway 192.0.2.1
        set device "wan1"
        set priority 7
    next
end
""")

    route = ir.routes[0]
    assert route.destination is None
    assert route.source_destination == "10.20.30.0 255.0.255.0"
    assert route.parse_error
    assert route.requires_manual_review is True
    assert route.priority == 7
    assert route.source_attributes == {}
    assert route.migration_status == "PARTIALLY_NORMALIZED"
    assert all(route.destination != value for value in ("0.0.0.0/0", "10.20.30.0/0"))
    assert any(entry.id == "route:20:destination" for entry in ir.audit_entries)


def test_invalid_address_is_preserved_without_inferred_prefix():
    ir = _transform("""
config firewall address
    edit "BROKEN"
        set subnet 10.20.30.0 255.0.255.0
    next
end
""")

    address = ir.addresses[0]
    assert address.subnet is None
    assert address.raw_value == "10.20.30.0 255.0.255.0"
    assert address.parse_error
    assert address.requires_manual_review is True
    assert address.value == "10.20.30.0 255.0.255.0"
    assert address.value not in {"10.20.30.0/16", "10.20.30.0/32", "10.20.30.0/0"}


def test_invalid_interface_and_remote_ip_are_unresolved_with_source_evidence():
    ir = _transform("""
config system interface
    edit "port1"
        set ip 10.0.0.1 255.0.255.0
    next
    edit "tunnel1"
        set type tunnel
        set remote-ip 10.10.10.1 255.0.255.0
    next
end
""")
    interfaces = {interface.name: interface for interface in ir.interfaces}

    assert interfaces["port1"].ip is None
    assert interfaces["port1"].source_attributes["ip"] == "10.0.0.1 255.0.255.0"
    assert interfaces["port1"].requires_manual_review is True
    assert interfaces["tunnel1"].remote_ip is None
    assert interfaces["tunnel1"].source_attributes["remote_ip"] == (
        "10.10.10.1 255.0.255.0"
    )
    assert interfaces["tunnel1"].requires_manual_review is True
    assert len([
        entry for entry in ir.audit_entries
        if entry.category == "Interface Network Normalization"
    ]) == 2


def test_vpn_helper_inference_ignores_malformed_route_and_interface_prefixes():
    ir = _transform("""
config system interface
    edit "port1"
        set role lan
        set ip 10.0.0.1 255.0.255.0
    next
end
config router static
    edit 1
        set dst 10.20.30.0 255.0.255.0
        set device "vpn1"
    next
end
config firewall address
    edit "vpn1_remote_subnet"
    next
    edit "vpn1_local_subnet"
    next
end
""")

    assert "vpn1_remote_subnet" not in {address.name for address in ir.addresses}
    assert "vpn1_local_subnet" not in {address.name for address in ir.addresses}


def test_network_parse_errors_make_coverage_partial_even_when_counts_match():
    result = extract_fortigate_config("""
config firewall address
    edit "BROKEN"
        set subnet 10.20.30.0 255.0.255.0
    next
end
config router static
    edit 1
        set dst 192.0.2.0 255.255.255.0
    next
    edit 2
        set dst 10.20.30.0 255.0.255.0
    next
end
""")
    sections = {section.path: section for section in result.source_sections}

    assert sections["firewall address"].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert sections["router static"].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert "1 static route(s)" in " ".join(sections["router static"].notes)
