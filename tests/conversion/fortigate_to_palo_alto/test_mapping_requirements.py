from fwmigrate.conversion.fortigate_to_palo_alto.decisions import build_decision_set
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPServer
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANMember
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1
from fwmigrate.vendors.fortigate.model.vpn_ssl import FGSSLVPNAuthenticationRule, FGSSLVPNClient, FGSSLVPNSettings
from fwmigrate.vendors.fortigate.model.zone import FGZone


def test_requirements_are_scoped_to_consumers_and_mappings():
    config = FGConfig(
        interfaces=[FGInterface(name=name, vdom=vdom) for vdom in ("root", "blue") for name in ("wan", "spare")],
        policies=[FGPolicy(vdom="root", srcintf=["wan"], dstintf=["dmz"])],
        zones=[FGZone(vdom="root", name="dmz", members=["wan"]), FGZone(vdom="blue", name="unused", members=["spare"])],
        static_routes=[FGStaticRoute(vdom="blue", device="wan")],
    )
    result = build_mapping_requirements(config, object())
    required = {(item["source_vdom"], item["source_name"]): item for item in result["interfaces"]}

    assert set(required) == {("root", "wan"), ("root", "dmz"), ("blue", "wan")}
    assert required[("root", "dmz")]["kind"] == "zone"
    assert "target_interface" in required[("root", "wan")]["requires"]
    assert ("blue", "unused") not in required


def test_same_interface_name_keeps_separate_vdom_requirements():
    config = FGConfig(policies=[
        FGPolicy(vdom="root", srcintf=["port1"]),
        FGPolicy(vdom="blue", srcintf=["port1"]),
    ])
    result = build_mapping_requirements(config, object())
    assert {(item["source_vdom"], item["source_name"]) for item in result["interfaces"]} == {
        ("root", "port1"), ("blue", "port1")
    }


def test_policy_interface_references_count_unique_affected_policies():
    config = FGConfig(policies=[
        FGPolicy(policy_id=1, srcintf=["port1"], dstintf=["port1"]),
        FGPolicy(policy_id=2, srcintf=["port1"]),
    ])
    item = build_mapping_requirements(config, object())["interfaces"][0]
    assert item["affected_count"] == 2
    assert item["affected_by"] == {"security_policy": 2}
    assert item["reference_count"] == 2


def test_same_interface_name_impact_stays_scoped_to_each_vdom():
    config = FGConfig(policies=[
        FGPolicy(policy_id=1, vdom="root", srcintf=["port1"]),
        FGPolicy(policy_id=1, vdom="blue", srcintf=["port1"]),
    ])
    items = {(item["source_vdom"], item["source_name"]): item for item in build_mapping_requirements(config, object())["interfaces"]}
    assert items[("root", "port1")]["affected_by"] == {"security_policy": 1}
    assert items[("blue", "port1")]["affected_by"] == {"security_policy": 1}


def test_same_name_interface_and_zone_keep_compatible_decision_fields():
    config = FGConfig(
        policies=[FGPolicy(vdom="root", srcintf=["port1"])],
        zones=[FGZone(vdom="root", name="port1", members=["member1"])],
        static_routes=[FGStaticRoute(vdom="root", device="port1")],
    )
    requirements = build_mapping_requirements(config, object())
    items = requirements["interfaces"]
    same_name = {(item["kind"], tuple(item["requires"])) for item in items if item["source_name"] == "port1"}

    assert same_name == {
        ("zone", ("target_zone",)),
        ("interface", ("target_interface", "target_zone")),
    }
    decisions = build_decision_set(config, object(), requirements)
    assert all(not (item.source_kind == "zone" and item.target_field == "target_interface") for item in decisions.decisions)


def test_non_policy_consumers_receive_interface_and_vdom_requirements_with_impact():
    config = FGConfig(
        interfaces=[FGInterface(name=name, vdom="blue") for name in ("dhcp0", "wan0", "dmz0", "client0")],
        dhcp_servers=[FGDHCPServer(id=7, vdom="blue", interface="dhcp0")],
        ipsec_phase1=[FGIPsecPhase1(name="ike-a", vdom="blue", interface="wan0")],
        sdwans=[FGSDWAN(vdom="blue", members=[FGSDWANMember(seq_num=10, interface="wan0")])],
        ssl_vpn_settings=[FGSSLVPNSettings(vdom="blue", source_interface=["wan0"], authentication_rules=[
            FGSSLVPNAuthenticationRule(id=4, source_interface=["dmz0"]),
        ])],
        ssl_vpn_clients=[FGSSLVPNClient(name="client-a", vdom="blue", interface="client0")],
        addresses=[FGAddress(name="host", vdom="blue", subnet="10.0.0.1 255.255.255.255")],
    )
    result = build_mapping_requirements(config, object())
    required = {(item["source_vdom"], item["source_name"]): item for item in result["interfaces"]}

    assert "target_interface" in required[("blue", "dhcp0")]["requires"]
    assert required[("blue", "dhcp0")]["affected_by"] == {"dhcp_server": 1}
    assert required[("blue", "wan0")]["affected_by"] == {
        "ipsec_phase1": 1, "sdwan_member": 1, "ssl_vpn": 1,
    }
    assert required[("blue", "dmz0")]["affected_by"] == {"ssl_vpn": 1}
    assert required[("blue", "client0")]["affected_by"] == {"ssl_vpn": 1}
    assert {item["source_vdom"] for item in result["vdoms"]} == {"blue"}
    assert "vsys" in next(item["requires"] for item in result["vdoms"] if item["source_vdom"] == "blue")
