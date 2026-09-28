import json

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    build_decision_set,
    make_decision_key,
)
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone


def test_decision_key_is_stable_and_scope_sensitive():
    key = make_decision_key("root", "interface", "port/1", "target_zone")
    assert key == make_decision_key("root", "interface", "port/1", "target_zone")
    assert key != make_decision_key("blue", "interface", "port/1", "target_zone")


def test_confirmation_and_serialization_round_trip():
    decision = PANMigrationDecision(
        "root", "interface", "port1", "target_interface",
        mode=PANDecisionMode.REQUIRED, affected_by={"static_route": 1},
    ).confirm("ethernet1/1")
    restored = PANMigrationDecisionSet.from_dict(json.loads(json.dumps(PANMigrationDecisionSet((decision,)).to_dict())))
    assert restored.decisions == (decision,)
    assert restored.decisions[0].review_state == PANDecisionReviewState.CONFIRMED


def test_requirements_generate_scoped_suggestions_without_defaults():
    config = FGConfig(
        interfaces=[FGInterface(name="port1")],
        zones=[FGZone(name="trust", members=["port1"])],
        policies=[
            FGPolicy(policy_id=1, srcintf=["port1"]),
            FGPolicy(policy_id=2, srcintf=["trust"]),
        ],
    )
    requirements = build_mapping_requirements(config, object())
    decisions = build_decision_set(config, object(), requirements)
    by_identity = {(item.source_kind, item.source_name, item.target_field): item for item in decisions.decisions}

    assert by_identity[("zone", "trust", "target_zone")].suggested_value == "trust"
    assert by_identity[("zone", "trust", "target_zone")].mode == PANDecisionMode.SUGGESTED
    assert by_identity[("zone", "trust", "target_zone")].evidence_source == "SOURCE"
    assert by_identity[("zone", "trust", "target_zone")].evidence_type == "SOURCE_ZONE_NAME"
    assert by_identity[("interface", "port1", "target_zone")].suggested_value == "trust"
    assert by_identity[("interface", "port1", "target_zone")].evidence_source == "SOURCE"
    assert by_identity[("interface", "port1", "target_interface")].mode == PANDecisionMode.REQUIRED
    assert by_identity[("vdom", "root", "vsys")].suggested_value is None
    assert by_identity[("vdom", "root", "virtual_router")].suggested_value is None
    assert decisions.to_options().interfaces == {}
    assert decisions.to_options().vdoms == {}


def test_confirmed_decisions_override_suggestions_and_convert_to_options():
    config = FGConfig(
        interfaces=[FGInterface(name="port1")],
        zones=[FGZone(name="trust", members=["port1"])],
        policies=[
            FGPolicy(policy_id=1, srcintf=["port1"]),
            FGPolicy(policy_id=2, srcintf=["trust"]),
        ],
    )
    requirements = build_mapping_requirements(config, object())
    initial = build_decision_set(config, object(), requirements)
    confirmed = tuple(
        item.confirm("vsys-prod" if item.target_field == "vsys" else "vr-prod" if item.target_field == "virtual_router" else "corp-trust" if item.target_field == "target_zone" else "ethernet1/7")
        for item in initial.decisions
    )
    updated = build_decision_set(config, object(), requirements, PANMigrationDecisionSet(confirmed))
    options = updated.to_options()

    assert options.vdoms["root"].vsys == "vsys-prod"
    assert options.vdoms["root"].virtual_router == "vr-prod"
    assert options.zones["root"]["trust"].target_zone == "corp-trust"
    assert options.interfaces["root"]["port1"].target_interface == "ethernet1/7"


def test_target_evidence_provenance_round_trips_and_requires_a_complete_identity():
    decision = PANMigrationDecision(
        "root", "interface", "port1", "target_interface",
        value="ethernet1/1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type="AUTOMATION_VERIFIED",
        evidence_target_digest="digest-a",
        evidence_target_device="fw-a",
        affected_by={},
    )
    restored = PANMigrationDecision.from_dict(json.loads(json.dumps(decision.to_dict())))
    assert restored == decision

    with pytest.raises(ValueError, match="digest and device"):
        PANMigrationDecision(
            "root", "interface", "port1", "target_interface",
            evidence_target_digest="digest-a",
        )
    with pytest.raises(ValueError, match="digest and device"):
        PANMigrationDecision(
            "root", "interface", "port1", "target_interface",
            evidence_target_device="fw-a",
        )


def test_build_decision_set_keeps_fresh_requirement_metadata_while_carrying_confirmation():
    config = FGConfig(
        interfaces=[FGInterface(name="port1")],
        zones=[FGZone(name="trust", members=["port1"])],
        policies=[FGPolicy(policy_id=1, srcintf=["port1"])],
    )
    requirements = build_mapping_requirements(config, object())
    fresh = build_decision_set(config, object(), requirements)
    original = next(
        item for item in fresh.decisions
        if item.source_kind == "interface"
        and item.source_name == "port1"
        and item.target_field == "target_zone"
    )
    previous = PANMigrationDecisionSet((
        PANMigrationDecision(
            original.source_vdom,
            original.source_kind,
            original.source_name,
            original.target_field,
            suggested_value="stale-zone",
            value="TRUST",
            mode=PANDecisionMode.REQUIRED,
            review_state=PANDecisionReviewState.CONFIRMED,
            reason="stale reason",
            evidence_source="ENGINEER",
            evidence_type="MANUAL",
            evidence_value="TRUST",
            target_object="TRUST",
        ),
    ))
    rebuilt = build_decision_set(config, object(), requirements, previous)
    carried = next(item for item in rebuilt.decisions if item.key == original.key)

    assert carried.value == "TRUST"
    assert carried.review_state is PANDecisionReviewState.CONFIRMED
    assert carried.suggested_value == "trust"
    assert carried.reason == original.reason
    assert carried.mode == original.mode
