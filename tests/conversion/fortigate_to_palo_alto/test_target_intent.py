import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_intent import (
    apply_target_intent, export_target_intent, parse_target_intent,
)
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone


def test_yaml_intent_confirms_only_existing_scoped_decisions_and_round_trips():
    config = FGConfig(interfaces=[FGInterface(name="agg1"), FGInterface(name="lan", vdom="blue")],
                      zones=[FGZone(name="LAN", vdom="blue")])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "agg1", "target_interface"),
        PANMigrationDecision("blue", "interface", "lan", "target_interface"),
        PANMigrationDecision("blue", "zone", "LAN", "target_zone"),
        PANMigrationDecision("blue", "vdom", "blue", "vsys"),
    ))
    text = "vdoms:\n  blue:\n    vsys: vsys2\ninterfaces:\n  agg1: ae1\n  blue/lan: ethernet1/2\nzones:\n  LAN: TRUST\n"
    updated = apply_target_intent(config, decisions, text)
    confirmed = {item.key: item for item in updated.decisions}
    assert all(item.review_state == PANDecisionReviewState.CONFIRMED for item in confirmed.values())
    assert confirmed[decisions.decisions[1].key].value == "ethernet1/2"
    assert parse_target_intent(export_target_intent(updated))["interfaces"]["blue/lan"]["interface"] == "ethernet1/2"


def test_target_intent_rejects_unknown_source_and_unsupported_decision():
    config = FGConfig(interfaces=[FGInterface(name="lan")])
    decisions = PANMigrationDecisionSet((PANMigrationDecision("root", "interface", "lan", "target_interface"),))
    with pytest.raises(ValueError, match="Unknown FortiGate interface"):
        apply_target_intent(config, decisions, {"interfaces": {"missing": "ethernet1/1"}})
    with pytest.raises(ValueError, match="only vdoms"):
        parse_target_intent({"target_config": {}})
