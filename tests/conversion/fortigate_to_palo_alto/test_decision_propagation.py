import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.decision_propagation import (
    apply_zone_to_members, dependent_decision_keys, zone_member_decision_keys,
)
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone


def test_confirmed_parent_reports_direct_children_for_re_evaluation():
    config = FGConfig(interfaces=[FGInterface(name="agg1"), FGInterface(name="vlan120", interface="agg1", vlanid=120)])
    parent = PANMigrationDecision("root", "interface", "agg1", "target_interface", value="ae1",
                                  review_state=PANDecisionReviewState.CONFIRMED)
    child = PANMigrationDecision("root", "interface", "vlan120", "target_interface")
    assert dependent_decision_keys(config, PANMigrationDecisionSet((parent, child)))[parent.key] == [child.key]


def test_zone_apply_confirms_only_explicit_same_vdom_member_decisions():
    config = FGConfig(
        interfaces=[FGInterface(name="lan", vdom="root"), FGInterface(name="lan", vdom="blue")],
        zones=[FGZone(name="USERS", vdom="root", members=["lan"], explicit_fields={"members"}),
               FGZone(name="USERS", vdom="blue", members=["lan"], explicit_fields={"members"})],
    )
    zone = PANMigrationDecision("root", "zone", "USERS", "target_zone", value="TRUST",
                                review_state=PANDecisionReviewState.CONFIRMED)
    root_member = PANMigrationDecision("root", "interface", "lan", "target_zone")
    blue_member = PANMigrationDecision("blue", "interface", "lan", "target_zone")
    decisions = PANMigrationDecisionSet((zone, root_member, blue_member))
    assert zone_member_decision_keys(config, decisions, zone.key) == [root_member.key]
    updated = apply_zone_to_members(config, decisions, source_key=zone.key, value="TRUST", apply_to=[root_member.key])
    confirmed = next(item for item in updated.decisions if item.key == root_member.key)
    untouched = next(item for item in updated.decisions if item.key == blue_member.key)
    assert confirmed.review_state == PANDecisionReviewState.CONFIRMED and confirmed.value == "TRUST"
    assert untouched.review_state == PANDecisionReviewState.PENDING
    with pytest.raises(ValueError, match="not an unresolved explicit zone member"):
        apply_zone_to_members(config, decisions, source_key=zone.key, value="TRUST", apply_to=[blue_member.key])
