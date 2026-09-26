from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.automation import (
    AutomationPolicy, run_automation_until_stable,
)
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


def _target(items):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    for item in items:
        item.scope = scope
    topology = [PANInterfaceTopologyEntry(item.name, pan_scope_identity(scope),
        parent=getattr(item, "parent", None), imported_vsys=getattr(item, "imported_vsys", ()),
        virtual_routers=getattr(item, "virtual_routers", ())) for item in items]
    return SimpleNamespace(config=SimpleNamespace(interfaces=items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=topology)), scope


def test_automation_is_off_by_default_and_fixed_point_applies_verified_then_derived():
    source = FGConfig(interfaces=[FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100)])
    before = source.model_dump()
    parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], tag=None, parent=None)
    child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=[], tag="100", parent="ethernet1/1")
    target, _ = _target([parent, child])
    decisions = PANMigrationDecisionSet(tuple(
        PANMigrationDecision("root", "interface", name, "target_interface")
        for name in ("port1", "vlan100")))

    off = run_automation_until_stable(source, None, decisions, target, "dev")
    assert not off.audit and all(item.review_state == PANDecisionReviewState.PENDING for item in off.decisions.decisions)

    result = run_automation_until_stable(source, None, decisions, target, "dev", enabled_policies=(
        AutomationPolicy.AUTO_APPLY_VERIFIED, AutomationPolicy.AUTO_APPLY_DERIVED))
    by_name = {item.source_name: item for item in result.decisions.decisions}
    assert by_name["port1"].value == "ethernet1/1"
    assert by_name["vlan100"].value == "ethernet1/1.100"
    assert [item["status"] for item in result.audit] == ["VERIFIED", "DERIVED"]
    assert all(item.evidence_source == "ENGINEER" and item.evidence_type == "ENGINEER_AUTOMATION_POLICY"
               for item in result.decisions.decisions)
    assert source.model_dump() == before
    assert result.stable


def test_automation_never_confirms_candidates_or_overwrites_engineer_values():
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="198.51.100.1/24")])
    items = [SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["198.51.100.1/24"], tag=None, parent=None)
             for name in ("ethernet1/1", "ethernet1/2")]
    target, _ = _target(items)
    confirmed = PANMigrationDecision("root", "interface", "other", "target_interface", value="ae1",
        review_state=PANDecisionReviewState.CONFIRMED)
    candidate = PANMigrationDecision("root", "interface", "lan", "target_interface")
    result = run_automation_until_stable(source, None, PANMigrationDecisionSet((confirmed, candidate)),
        target, "dev", enabled_policies=tuple(AutomationPolicy))
    by_key = {item.key: item for item in result.decisions.decisions}
    assert by_key[confirmed.key].value == "ae1"
    assert by_key[candidate.key].review_state == PANDecisionReviewState.PENDING
    assert not result.audit


def test_target_conflict_stops_parent_propagation():
    source = FGConfig(interfaces=[FGInterface(name="port1"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100)])
    child = SimpleNamespace(name="ae1.100", interface_family="vlan", ipv4_addresses=[], tag="100", parent="ae1")
    target, _ = _target([child])
    parent = PANMigrationDecision("root", "interface", "port1", "target_interface", value="ae1",
        review_state=PANDecisionReviewState.CONFIRMED, evidence_source="ENGINEER")
    vlan = PANMigrationDecision("root", "interface", "vlan100", "target_interface")
    result = run_automation_until_stable(source, None, PANMigrationDecisionSet((parent, vlan)), target, "dev",
        enabled_policies=tuple(AutomationPolicy))
    assert not result.audit
    assert next(item for item in result.decisions.decisions if item.key == vlan.key).review_state == PANDecisionReviewState.PENDING
