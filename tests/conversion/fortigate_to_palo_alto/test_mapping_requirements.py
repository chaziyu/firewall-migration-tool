from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone


def test_requirements_are_scoped_and_only_include_policy_route_dependencies():
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
