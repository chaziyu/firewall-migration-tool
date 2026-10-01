from dataclasses import replace
from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.application.review import build_review_state
from fwmigrate.conversion.fortigate_to_palo_alto.application.decision_documents import build_decision_document
from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionMode, PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.review.review_suggestions import apply_review_suggestions
from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import discover_target_candidates
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


def _target(names=("ethernet1/1",), *, zones=("trust",), vsys=("vsys1",)):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    items = [SimpleNamespace(name=name, scope=scope, interface_family="ethernet", tag=None,
        parent=None, ipv4_addresses=["192.0.2.1/24"], comment=None) for name in names]
    return SimpleNamespace(config=SimpleNamespace(interfaces=items, interface_units=[], zones=[],
        virtual_routers=[], scopes=[]), derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry(item.name, pan_scope_identity(scope), zones=zones,
                imported_vsys=vsys, virtual_routers=("vr-main",)) for item in items]))


def test_verified_interface_prefills_without_becoming_options_or_commands():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24")],
        static_routes=[FGStaticRoute(seq_num=1, device="lan", dst="0.0.0.0/0", gateway="192.0.2.254")])
    target = _target()
    state = build_review_state(config, build_derived_views(config), "source", target=target, target_device="dev")
    decisions = state["decisions"]
    interface = next(item for item in decisions.decisions if item.target_field == "target_interface")
    assert interface.suggested_value == "ethernet1/1" and interface.evidence_source == "TARGET"
    assert all(item.value is None and item.review_state is PANDecisionReviewState.PENDING for item in decisions.decisions)
    assert decisions.to_options().interfaces == decisions.to_options().vdoms == {}
    assert state["design_session"].decisions == decisions
    result = run_migration_pipeline(config, build_derived_views(config), decisions=decisions)
    assert result.rendered.commands == ()
    assert all(group["queue"] == "READY_TO_CONFIRM" for group in state["review_workflow"]["review_groups"])


def test_confirmed_source_zone_refresh_prefills_member_with_derived_provenance():
    config = FGConfig(interfaces=[FGInterface(name="lan")],
        zones=[FGZone(name="USERS", members=["lan"], explicit_fields={"members"})],
        policies=[FGPolicy(policy_id=1, srcintf=["lan"]), FGPolicy(policy_id=2, srcintf=["USERS"])])
    first = build_review_state(config, build_derived_views(config), "source")
    previous = PANMigrationDecisionSet(tuple(item.confirm("TRUST") if item.source_kind == "zone" else item
        for item in first["decisions"].decisions))
    state = build_review_state(config, build_derived_views(config), "source",
        previous_document=build_decision_document("source", previous))
    member = next(item for item in state["decisions"].decisions if item.source_kind == "interface" and item.target_field == "target_zone")
    assert member.suggested_value == "TRUST" and member.value is None
    assert member.evidence_source == "DERIVED" and member.evidence_target_digest is None
    assert member.review_state is PANDecisionReviewState.PENDING
    assert state["decisions"].to_options().interfaces == {}


@pytest.mark.parametrize("names", [("ethernet1/1", "ethernet1/2"), ("ethernet1/1", "ethernet1/1")])
def test_ambiguous_interfaces_have_candidates_without_prefill(names):
    config = FGConfig(interfaces=[FGInterface(name="lan", ip="192.0.2.1/24")])
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    decisions = PANMigrationDecisionSet((decision,))
    target = _target(names)
    results = classify_auto_decisions(config, None, decisions, target, "dev")
    updated = apply_review_suggestions(decisions, results,
        candidates=discover_target_candidates(config, decisions, target, "dev"))
    assert updated.decisions[0].suggested_value is None


def test_confirmed_and_unsupported_decisions_survive_suggestion_recomputation():
    pending = PANMigrationDecision("root", "interface", "lan", "target_zone")
    decisions = PANMigrationDecisionSet((pending.confirm("chosen"), replace(pending,
        source_name="other", mode=PANDecisionMode.UNSUPPORTED)))
    results = {item.key: {"status": "DERIVED", "value": "trust", "reason": "new evidence"} for item in decisions.decisions}
    assert apply_review_suggestions(decisions, results) == decisions


def test_target_zone_derivation_is_pending_and_target_backed():
    config = FGConfig(interfaces=[FGInterface(name="lan", ip="192.0.2.1/24")])
    decision = PANMigrationDecision("root", "interface", "lan", "target_zone")
    decisions = PANMigrationDecisionSet((decision,))
    results = classify_auto_decisions(config, None, decisions, _target(), "dev")
    updated = apply_review_suggestions(decisions, results).decisions[0]
    assert updated.suggested_value == "trust" and updated.evidence_source == "TARGET"
    assert updated.evidence_type == "REVIEW_DERIVED_SUGGESTION" and updated.value is None


def test_confirmed_parent_refresh_unlocks_vlan_child_without_confirmation():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="lan", vlanid=100)],
        static_routes=[FGStaticRoute(seq_num=1, device="vlan100", dst="0.0.0.0/0")])
    target = _target(zones=())
    child = SimpleNamespace(name="ethernet1/1.100", scope=target.config.interfaces[0].scope,
        interface_family="ethernet", tag="100", parent="ethernet1/1", ipv4_addresses=[], comment=None)
    target.config.interface_units.append(child)
    target.derived.interface_topology.append(PANInterfaceTopologyEntry(child.name,
        pan_scope_identity(child.scope), parent=child.parent, imported_vsys=("vsys1",), virtual_routers=("vr-main",)))
    first = build_review_state(config, build_derived_views(config), "source", target=target, target_device="dev")
    previous = PANMigrationDecisionSet(tuple(item.confirm("ethernet1/1")
        if item.source_name == "lan" and item.target_field == "target_interface" else item
        for item in first["decisions"].decisions))
    child_before = next(item for item in previous.decisions if item.source_name == "vlan100")
    assert child_before.suggested_value is None
    refreshed = build_review_state(config, build_derived_views(config), "source", target=target, target_device="dev",
        previous_document=build_decision_document("source", previous))
    child_after = next(item for item in refreshed["decisions"].decisions if item.key == child_before.key)
    assert child_after.suggested_value == child.name and child_after.value is None
    assert child_after.review_state is PANDecisionReviewState.PENDING


def test_refresh_recomputes_pending_target_suggestions_and_removes_absent_evidence():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24")],
        static_routes=[FGStaticRoute(seq_num=1, device="lan", dst="0.0.0.0/0")])
    derived = build_derived_views(config)
    metadata = {"vendor": "palo_alto", "config_digest": "first", "device": "dev"}
    first = build_review_state(config, derived, "source", target=_target(), target_device="dev", target_metadata=metadata)
    document = build_decision_document("source", first["decisions"], metadata)
    refreshed = build_review_state(config, derived, "source", previous_document=document,
        target=_target(("ethernet1/2",)), target_device="dev", target_metadata={**metadata, "config_digest": "second"})
    interface = next(item for item in refreshed["decisions"].decisions if item.target_field == "target_interface")
    assert interface.suggested_value == "ethernet1/2" and interface.review_state is PANDecisionReviewState.PENDING
    assert refreshed["target_evidence_changed"]
    removed = build_review_state(config, derived, "source", previous_document=document)
    assert all(item.suggested_value is None and item.value is None for item in removed["decisions"].decisions)


def test_confirmed_review_mappings_produce_the_same_rendering_as_explicit_options():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24")],
        static_routes=[FGStaticRoute(seq_num=1, device="lan", dst="0.0.0.0/0", gateway="192.0.2.254")])
    derived = build_derived_views(config)
    state = build_review_state(config, derived, "source", target=_target(), target_device="dev")
    confirmed = PANMigrationDecisionSet(tuple(item.confirm(item.suggested_value) for item in state["decisions"].decisions))
    reviewed = run_migration_pipeline(config, derived, decisions=confirmed)
    explicit = run_migration_pipeline(config, derived, options=confirmed.to_options())
    assert reviewed.rendered.commands and reviewed.rendered.commands == explicit.rendered.commands
    assert reviewed.plan == explicit.plan
