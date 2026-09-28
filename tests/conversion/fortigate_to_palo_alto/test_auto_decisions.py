from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


def _target(items):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    for item in items:
        item.scope = scope
    topology = [PANInterfaceTopologyEntry(item.name, pan_scope_identity(scope),
        parent=getattr(item, "parent", None), imported_vsys=getattr(item, "imported_vsys", ()),
        zones=getattr(item, "zones", ()),
        virtual_routers=getattr(item, "virtual_routers", ())) for item in items]
    return SimpleNamespace(config=SimpleNamespace(interfaces=items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=topology)), scope


def test_exact_ip_verifies_and_confirmed_parent_derives_vlan_without_mutating_decisions():
    source = FGConfig(interfaces=[FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100)])
    parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], tag=None, parent=None)
    child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=[], tag="100", parent="ethernet1/1")
    target, _ = _target([parent, child])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "port1", "target_interface", value="ethernet1/1", review_state=PANDecisionReviewState.CONFIRMED),
        PANMigrationDecision("root", "interface", "vlan100", "target_interface"),
    ))
    result = classify_auto_decisions(source, None, decisions, target, "dev")
    child_decision = decisions.decisions[1]
    assert result[child_decision.key]["status"] == "DERIVED"
    assert result[child_decision.key]["value"] == "ethernet1/1.100"
    assert result[child_decision.key]["uses_target_evidence"] is True
    assert child_decision.review_state == PANDecisionReviewState.PENDING


def test_exact_address_is_verified_and_multiple_exact_targets_remain_candidates():
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="198.51.100.1/24")])
    targets = [SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["198.51.100.1/24"], tag=None, parent=None)
               for name in ("ethernet1/1", "ethernet1/2")]
    target, _ = _target(targets)
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    result = classify_auto_decisions(source, None, PANMigrationDecisionSet((decision,)), target, "dev")
    assert result[decision.key]["status"] == "CANDIDATE"

    one, _ = _target(targets[:1])
    result = classify_auto_decisions(source, None, PANMigrationDecisionSet((decision,)), one, "dev")
    assert result[decision.key]["status"] == "VERIFIED"
    assert result[decision.key]["uses_target_evidence"] is True


def test_vsys_and_virtual_router_derive_only_when_all_mapped_interfaces_agree():
    source = FGConfig(interfaces=[FGInterface(name="port1"), FGInterface(name="port2")])
    first = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=[], tag=None,
                            parent=None, imported_vsys=("vsys1",), virtual_routers=("vr-main",))
    second = SimpleNamespace(name="ethernet1/2", interface_family="ethernet", ipv4_addresses=[], tag=None,
                             parent=None, imported_vsys=("vsys1",), virtual_routers=("vr-main",))
    target, _ = _target([first, second])
    mapped = [PANMigrationDecision("root", "interface", name, "target_interface", value=target_name,
        review_state=PANDecisionReviewState.CONFIRMED)
        for name, target_name in (("port1", "ethernet1/1"), ("port2", "ethernet1/2"))]
    vdom = [PANMigrationDecision("root", "vdom", "root", field) for field in ("vsys", "virtual_router")]
    decisions = PANMigrationDecisionSet(tuple((*mapped, *vdom)))
    result = classify_auto_decisions(source, None, decisions, target, "dev")
    assert result[vdom[0].key]["status"] == "DERIVED"
    assert result[vdom[0].key]["value"] == "vsys1"
    assert result[vdom[0].key]["reason"] == "Consistent deterministic interface vsys evidence."
    assert result[vdom[0].key]["uses_target_evidence"] is True
    assert result[vdom[1].key]["status"] == "DERIVED"

    second.virtual_routers = ("vr-other",)
    target, _ = _target([first, second])
    result = classify_auto_decisions(source, None, decisions, target, "dev")
    assert result[vdom[0].key]["status"] == "DERIVED"
    assert result[vdom[1].key]["status"] == "MANUAL"


def test_zone_and_vsys_derive_from_unique_exact_interface_without_target_interface_requirement():
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="192.0.2.1/24")])
    target_item = SimpleNamespace(
        name="ethernet1/1", interface_family="ethernet",
        ipv4_addresses=["192.0.2.1/24"], tag=None, parent=None,
        imported_vsys=("vsys1",), zones=("trust",), virtual_routers=("vr-main",),
    )
    target, _ = _target([target_item])
    zone = PANMigrationDecision("root", "interface", "lan", "target_zone")
    vsys = PANMigrationDecision("root", "vdom", "root", "vsys")
    decisions = PANMigrationDecisionSet((zone, vsys))

    result = classify_auto_decisions(source, None, decisions, target, "dev")

    assert result[zone.key]["status"] == "DERIVED"
    assert result[zone.key]["value"] == "trust"
    assert result[zone.key]["uses_target_evidence"] is True
    assert result[vsys.key]["status"] == "DERIVED"
    assert result[vsys.key]["value"] == "vsys1"


def test_zone_derivation_from_explicit_source_membership_is_not_target_backed():
    source = FGConfig(
        interfaces=[FGInterface(name="lan")],
        zones=[FGZone(name="USERS", members=["lan"], explicit_fields={"members"})],
    )
    zone_mapping = PANMigrationDecision(
        "root", "zone", "USERS", "target_zone",
        value="TRUST",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="ENGINEER",
        evidence_type="TARGET_INTENT",
    )
    interface_zone = PANMigrationDecision("root", "interface", "lan", "target_zone")
    result = classify_auto_decisions(
        source,
        None,
        PANMigrationDecisionSet((zone_mapping, interface_zone)),
    )
    assert result[interface_zone.key]["status"] == "DERIVED"
    assert result[interface_zone.key]["value"] == "TRUST"
    assert result[interface_zone.key]["uses_target_evidence"] is False
