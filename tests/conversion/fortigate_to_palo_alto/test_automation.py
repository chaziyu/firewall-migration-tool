from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.automation import (
    AutomationPolicy, run_automation_until_stable,
)
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

    result = run_automation_until_stable(
        source, None, decisions, target, "dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-a", "device": "dev"},
        enabled_policies=(
            AutomationPolicy.AUTO_APPLY_VERIFIED,
            AutomationPolicy.AUTO_APPLY_DERIVED,
        ),
    )
    by_name = {item.source_name: item for item in result.decisions.decisions}
    assert by_name["port1"].value == "ethernet1/1"
    assert by_name["vlan100"].value == "ethernet1/1.100"
    assert [item["status"] for item in result.audit] == ["VERIFIED", "DERIVED"]
    assert all(item.evidence_source == "DERIVED" and item.evidence_type in {"AUTOMATION_VERIFIED", "AUTOMATION_DERIVED"}
               for item in result.decisions.decisions)
    assert all(item.evidence_target_digest == "digest-a" and item.evidence_target_device == "dev"
               for item in result.decisions.decisions)
    assert all(item["uses_target_evidence"] is True and item["target_digest"] == "digest-a"
               for item in result.audit)
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


def test_target_backed_automation_fails_closed_without_durable_target_identity():
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="198.51.100.1/24")])
    target_item = SimpleNamespace(
        name="ethernet1/1", interface_family="ethernet",
        ipv4_addresses=["198.51.100.1/24"], tag=None, parent=None,
    )
    target, _ = _target([target_item])
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")

    with pytest.raises(ValueError, match="target-backed automation requires"):
        run_automation_until_stable(
            source,
            None,
            PANMigrationDecisionSet((decision,)),
            target,
            "dev",
            enabled_policies=(AutomationPolicy.AUTO_APPLY_VERIFIED,),
        )


def test_source_only_derived_automation_does_not_require_or_store_target_identity():
    source = FGConfig(
        interfaces=[FGInterface(name="lan")],
        zones=[FGZone(name="USERS", members=["lan"], explicit_fields={"members"})],
    )
    zone = PANMigrationDecision(
        "root", "zone", "USERS", "target_zone",
        value="TRUST",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="ENGINEER",
        evidence_type="TARGET_INTENT",
    )
    interface_zone = PANMigrationDecision("root", "interface", "lan", "target_zone")
    result = run_automation_until_stable(
        source,
        None,
        PANMigrationDecisionSet((zone, interface_zone)),
        enabled_policies=(AutomationPolicy.AUTO_APPLY_DERIVED,),
    )
    mapped = next(item for item in result.decisions.decisions if item.key == interface_zone.key)
    assert mapped.review_state is PANDecisionReviewState.CONFIRMED
    assert mapped.value == "TRUST"
    assert mapped.evidence_target_digest is None
    assert mapped.evidence_target_device is None
    assert result.audit[0]["uses_target_evidence"] is False
