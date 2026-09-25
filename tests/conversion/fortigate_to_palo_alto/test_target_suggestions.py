from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import suggest_from_target
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import _compatible


def test_redundant_source_interface_is_not_assumed_to_be_aggregate():
    source = SimpleNamespace(type="redundant", vlanid=None)
    target = SimpleNamespace(interface_family="aggregate-ethernet", tag=None)
    assert _compatible(source, target) is False


def test_same_subnet_vlan_and_mapped_parent_is_a_unique_candidate():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[
        FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100, ip="10.0.0.1/24"),
    ])
    target_parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], scope=scope, tag=None, parent=None)
    target_child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=["10.0.0.2/24"], scope=scope, tag="100", parent="ethernet1/1")
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=[target_parent], interface_units=[target_child], zones=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", identity),
            PANInterfaceTopologyEntry("ethernet1/1.100", identity, parent="ethernet1/1"),
        ]),
    )
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision("root", "interface", name, "target_interface") for name in ("port1", "vlan100")))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    values = {item.source_name: item.suggested_value for item in updated.decisions}
    assert values["port1"] == "ethernet1/1"
    assert values["vlan100"] == "ethernet1/1.100"


def test_equally_valid_target_candidates_stay_pending_with_warning():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="10.0.0.1/24")])
    target_items = [SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"], scope=scope, tag=None, parent=None) for name in ("ethernet1/1", "ethernet1/2")]
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=target_items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(item.name, identity) for item in target_items]),
    )
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    updated, warnings = suggest_from_target(source, PANMigrationDecisionSet((decision,)), target, "dev")
    assert updated.decisions[0].suggested_value is None
    assert decision.key in warnings


def test_confirmed_vsys_limits_interface_candidates_to_imported_vsys():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="10.0.0.1/24")])
    target_items = [
        SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"],
                        scope=scope, tag=None, parent=None)
        for name in ("ethernet1/1", "ethernet1/2")
    ]
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=target_items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", identity, imported_vsys=("vsys1",)),
            PANInterfaceTopologyEntry("ethernet1/2", identity, imported_vsys=("vsys2",)),
        ]),
    )
    vsys = PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys2",
                                review_state=PANDecisionReviewState.CONFIRMED)
    interface = PANMigrationDecision("root", "interface", "lan", "target_interface")
    updated, _ = suggest_from_target(source, PANMigrationDecisionSet((vsys, interface)), target, "dev")
    assert updated.decisions[1].suggested_value == "ethernet1/2"
