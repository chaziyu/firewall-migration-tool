from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "interfaces_extended.xml"


def _result():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def _interface_item(result, name, mode):
    return next(item for item in result.inventory_items if item.domain == "interfaces" and item.name == name
                and item.source_attributes.get("pan_interface_mode") == mode)


def test_layer3_addresses_ipv6_management_and_physical_fields_are_preserved():
    result = _result()
    intf = next(item for item in result.canonical_ir.interfaces if item.name == "ethernet1/1")
    assert intf.ip == "192.0.2.1/24"
    assert intf.management_profile == "allow-ping"
    attrs = _interface_item(result, "ethernet1/1", "layer3").source_attributes
    assert attrs["pan_ipv4_addresses"] == ["192.0.2.1/24", "192.0.2.10/24"]
    assert attrs["pan_ipv6_addresses"][0]["address"] == "2001:db8::1/64"
    assert attrs["pan_link_state"] == "auto"
    assert attrs["pan_speed"] == "auto" and attrs["pan_duplex"] == "auto"
    assert "future-l3" in attrs["pan_unknown_layer3_fields"]


def test_layer3_and_layer2_subinterfaces_preserve_parent_and_tag():
    result = _result()
    l3 = next(item for item in result.canonical_ir.interfaces if item.name == "ethernet1/1.10")
    assert (l3.parent, l3.vlanid) == ("ethernet1/1", 10)
    l2 = _interface_item(result, "ethernet1/2.20", "layer2-subinterface")
    assert l2.status == ExtractionStatus.EXTRACT_ONLY
    assert l2.source_attributes["pan_parent_interface"] == "ethernet1/2"
    assert l2.source_attributes["pan_vlan_tag"] == "20"
    assert "future-l2" in l2.source_attributes["pan_unknown_fields"]


def test_non_layer3_modes_are_structured_without_canonical_l3_interfaces():
    result = _result()
    expected = {
        ("ethernet1/2", "layer2"), ("ethernet1/3", "virtual-wire"),
        ("ethernet1/4", "tap"), ("ethernet1/5", "ha"),
        ("ethernet1/6", "decrypt-mirror"), ("ae1", "layer2"),
    }
    assert expected <= {(item.name, item.source_attributes.get("pan_interface_mode"))
                        for item in result.inventory_items if item.domain == "interfaces"}
    canonical_names = {item.name for item in result.canonical_ir.interfaces}
    assert not {name for name, _ in expected} & canonical_names


def test_logical_interfaces_and_link_state_values_are_not_invented():
    result = _result()
    assert {"loopback.1", "tunnel.1", "vlan.20"} <= {item.name for item in result.canonical_ir.interfaces}
    assert next(item for item in result.canonical_ir.interfaces if item.name == "tunnel.1").addressing_mode == "dhcp-client"
    assert _interface_item(result, "ethernet1/1", "layer3").source_attributes["pan_link_state"] == "auto"
    assert _interface_item(result, "ethernet1/2", "layer2").source_attributes["pan_link_state"] == "up"
    assert _interface_item(result, "ethernet1/3", "virtual-wire").source_attributes["pan_link_state"] == "down"


def test_vsys_import_and_unknown_interface_family_are_accounted():
    result = _result()
    assert _interface_item(result, "ethernet1/1", "layer3").source_attributes["pan_vsys"] == "vsys1"
    assert _interface_item(result, "ethernet1/2.20", "layer2-subinterface").source_attributes["pan_vsys"] == "vsys1"
    future = next(item for item in result.inventory_items if item.source_path == "network/interface/future-interface-family")
    assert future.status == ExtractionStatus.UNSUPPORTED
    assert "keep-family" in str(future.source_attributes["pan_source_entry"])
