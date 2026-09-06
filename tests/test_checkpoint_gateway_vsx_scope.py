from fwmigrate.ir.core import IRInterface
from fwmigrate.parsers.checkpoint.gateways import extract_gateway_topology
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver


def _gaia_interfaces():
    return [
        IRInterface(
            name="eth0", ip="10.2.0.1/24", source_context="VSX-GW:vsid=2",
            source_attributes={"virtual_system_id": 2},
        ),
        IRInterface(
            name="eth0", ip="10.5.0.1/24", source_context="VSX-GW:vsid=5",
            source_attributes={"virtual_system_id": 5},
        ),
    ]


def test_unscoped_management_topology_never_collapses_same_name_vsx_interfaces():
    response = CheckPointResponse(
        command="show-gateways-and-servers", domain="D1",
        data={"objects": [{
            "uid": "gw", "name": "VSX-GW", "type": "CpmiGatewayPlain",
            "interfaces": [{
                "name": "eth0", "ipv4-address": "192.0.2.1",
                "ipv4-network-mask": "255.255.255.0",
            }],
        }]},
    )
    interfaces, _, inventory, _ = extract_gateway_topology(
        [response], CheckPointObjectResolver(), _gaia_interfaces(),
    )
    eth0 = [item for item in interfaces if item.name == "eth0"]
    assert len(eth0) == 2
    assert {item.ip for item in eth0} == {"10.2.0.1/24", "10.5.0.1/24"}
    assert all(item.requires_manual_review for item in eth0)
    assert all(
        "ambiguous-management-topology-across-virtual-systems" in item.review_reasons
        for item in eth0
    )
    gateway = next(item for item in inventory if item.name == "VSX-GW")
    assert "eth0:ambiguous-management-topology-across-virtual-systems" in gateway.notes


def test_explicit_management_vsid_matches_only_that_gaia_interface_and_never_overwrites_ip():
    response = CheckPointResponse(
        command="show-gateways-and-servers", domain="D1",
        data={"objects": [{
            "uid": "gw", "name": "VSX-GW", "type": "CpmiGatewayPlain",
            "interfaces": [{
                "name": "eth0", "virtual-system-id": 2,
                "ipv4-address": "192.0.2.1", "ipv4-network-mask": "255.255.255.0",
            }],
        }]},
    )
    interfaces, _, _, _ = extract_gateway_topology(
        [response], CheckPointObjectResolver(), _gaia_interfaces(),
    )
    by_vsid = {item.source_attributes.get("virtual_system_id"): item for item in interfaces if item.name == "eth0"}
    assert by_vsid[2].ip == "10.2.0.1/24"
    assert by_vsid[2].source_attributes["management_ipv4"] == "192.0.2.1/24"
    assert "gaia-management-ip-conflict" in by_vsid[2].review_reasons
    assert by_vsid[5].ip == "10.5.0.1/24"
    assert "management_ipv4" not in by_vsid[5].source_attributes
