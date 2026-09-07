from fwmigrate.ir.core import IRCheckpointInterfaceContext, IRInterface
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


def test_same_interface_name_on_two_gateways_keeps_typed_owners():
    response = CheckPointResponse(
        command="show-gateways-and-servers", domain="D1",
        data={"objects": [
            {"uid": "gw-a", "name": "GW-A", "type": "simple-gateway",
             "interfaces": [{"name": "eth0", "ipv4-address": "192.0.2.1",
                              "ipv4-network-mask": "255.255.255.0"}]},
            {"uid": "gw-b", "name": "GW-B", "type": "simple-gateway",
             "interfaces": [{"name": "eth0", "ipv4-address": "192.0.2.2",
                              "ipv4-network-mask": "255.255.255.0"}]},
        ]},
    )
    interfaces, _, _, _ = extract_gateway_topology(
        [response], CheckPointObjectResolver(), [IRInterface(
            name="eth0", ip="10.0.0.1/24",
            checkpoint_context=IRCheckpointInterfaceContext(
                domain_name="D1", gaia_gateway_name="GW-A",
            ),
        )],
    )

    eth0 = [item for item in interfaces if item.name == "eth0"]
    assert len(eth0) == 2
    assert {item.checkpoint_context.management_gateway_uid for item in eth0} == {"gw-a", "gw-b"}
    assert next(item for item in eth0 if item.checkpoint_context.management_gateway_uid == "gw-a").ip == "10.0.0.1/24"


def test_unrelated_management_gateway_cannot_mutate_gaia_owner():
    response = CheckPointResponse(
        command="show-gateways-and-servers", domain="D1",
        data={"objects": [
            {"uid": "gw-a", "name": "GW-A", "type": "simple-gateway",
             "interfaces": [{"name": "eth0", "ipv4-address": "192.0.2.1",
                              "ipv4-network-mask": "255.255.255.0"}]},
            {"uid": "gw-b", "name": "GW-B", "type": "simple-gateway",
             "interfaces": [{"name": "eth0", "ipv4-address": "198.51.100.2",
                              "ipv4-network-mask": "255.255.255.0"}]},
        ]},
    )
    interfaces, _, _, _ = extract_gateway_topology(
        [response], CheckPointObjectResolver(), [IRInterface(
            name="eth0", ip="10.0.0.1/24",
            checkpoint_context=IRCheckpointInterfaceContext(
                domain_name="D1", gaia_gateway_name="GW-A",
            ),
        )],
    )

    by_gateway = {
        item.checkpoint_context.management_gateway_uid: item
        for item in interfaces if item.name == "eth0"
    }
    assert by_gateway["gw-a"].ip == "10.0.0.1/24"
    assert by_gateway["gw-b"].ip == "198.51.100.2/24"
    assert by_gateway["gw-b"].checkpoint_context.management_gateway_name == "GW-B"


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
    assert all(item.checkpoint_context is None for item in eth0)
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
    assert by_vsid[2].checkpoint_context.management_gateway_uid == "gw"
    assert by_vsid[2].checkpoint_context.virtual_system_id == 2
    assert by_vsid[2].source_attributes["management_ipv4"] == "192.0.2.1/24"
    assert "gaia-management-ip-conflict" in by_vsid[2].review_reasons
    assert by_vsid[5].ip == "10.5.0.1/24"
    assert "management_ipv4" not in by_vsid[5].source_attributes


def test_non_vsx_security_zone_definition_and_binding_remain_one_zone():
    responses = [
        CheckPointResponse(
            command="show-security-zones", domain="D1",
            data={"objects": [{"uid": "zone-1", "name": "Internal", "type": "security-zone"}]},
        ),
        CheckPointResponse(
            command="show-gateways-and-servers", domain="D1",
            data={"objects": [{
                "uid": "gw", "name": "GW", "type": "CpmiGatewayPlain",
                "interfaces": [{
                    "name": "eth1", "security-zone": {"uid": "zone-1", "name": "Internal"},
                }],
            }]},
        ),
    ]
    interfaces, zones, _, _ = extract_gateway_topology(
        responses, CheckPointObjectResolver(), [IRInterface(name="eth1")],
    )
    assert next(item for item in interfaces if item.name == "eth1").zone == "Internal"
    internal = [zone for zone in zones if zone.name == "Internal"]
    assert len(internal) == 1
    assert internal[0].interfaces == ["eth1"]
