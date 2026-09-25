import json

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
        policies=[FGPolicy(policy_id=1, srcintf=["port1"])],
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
        policies=[FGPolicy(policy_id=1, srcintf=["port1"])],
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
    assert options.interfaces["root"]["trust"].target_zone == "corp-trust"
    assert options.interfaces["root"]["port1"].target_interface == "ethernet1/7"
