from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "dynamic_routing.xml"


def _result():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def _items(result, domain):
    return [item for item in result.inventory_items if item.domain == domain]


def test_bgp_instances_peer_groups_and_multiple_peers_are_source_only():
    result = _result()
    bgp = _items(result, "dynamic_routing:bgp")
    assert {(item.source_attributes.get("virtual_router_name"), item.source_attributes.get("logical_router_name")) for item in bgp} == {
        ("vr-a", None), ("vr-b", None), (None, "lr-a")}
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in bgp)
    assert len(_items(result, "dynamic_routing:bgp_peer_group")) == 2
    assert len(_items(result, "dynamic_routing:bgp_peer")) == 3


def test_bgp_peer_references_bfd_addresses_and_unknown_fields_are_preserved():
    peer = next(item for item in _items(_result(), "dynamic_routing:bgp_peer")
                if item.source_attributes["virtual_router_name"] == "vr-a" and item.name == "peer-common")
    attrs = peer.source_attributes
    assert attrs["peer_as"] == "65002"
    assert attrs["peer_address"] == "192.0.2.2"
    assert attrs["local_address"] == "192.0.2.1"
    assert attrs["interface"] == "ethernet1/1"
    assert attrs["bfd_profile"] == "rapid-bfd"
    assert "hold-time" in str(attrs["timers"]["connection-options"])
    assert "future-peer-field" in attrs["unknown_fields"]


def test_ospf_ospfv3_rip_and_redistribution_are_structured():
    result = _result()
    ospf = _items(result, "dynamic_routing:ospf_interface")[0].source_attributes
    assert (ospf["area_id"], ospf["cost"], ospf["priority"], ospf["passive"], ospf["network_type"]) == (
        "0.0.0.0", 10, 50, False, "broadcast")
    assert ospf["bfd_profile"] == "rapid-bfd"
    assert _items(result, "dynamic_routing:ospfv3_interface")[0].source_attributes["passive"] is True
    assert _items(result, "dynamic_routing:rip")[0].source_attributes["interfaces"] == ["ethernet1/4"]
    redist = _items(result, "dynamic_routing:redistribution_profile")[0].source_attributes
    assert redist["protocol_references"] == ["connect"]
    assert "future-redist" in redist["unknown_fields"]


def test_overlapping_names_keep_routing_instance_identity_and_vsys_import():
    peers = [item for item in _items(_result(), "dynamic_routing:bgp_peer") if item.name == "peer-common"]
    assert {item.source_attributes["virtual_router_name"] for item in peers} == {"vr-a", "vr-b"}
    imported = next(item for item in peers if item.source_attributes["virtual_router_name"] == "vr-a")
    assert imported.source_attributes["pan_vsys"] == "vsys1"


def test_unknown_dynamic_protocol_is_explicitly_unsupported():
    item = _items(_result(), "dynamic_routing:future-protocol")[0]
    assert item.status == ExtractionStatus.UNSUPPORTED
    assert "keep" in str(item.source_attributes["pan_source_entry"])
