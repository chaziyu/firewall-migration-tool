import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.decision_propagation import (
    MigrationRuleType, apply_zone_to_members, dependent_decision_keys,
    apply_repeated_zone_action, repeated_zone_action_suggestions,
    rule_affected_decision_keys, zone_member_decision_keys,
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


def test_confirmed_vdom_and_interface_mapping_expose_only_same_vdom_dependents():
    config = FGConfig(interfaces=[FGInterface(name="agg1", type="aggregate"),
        FGInterface(name="vlan120", interface="agg1", vlanid=120, vdom="root"),
        FGInterface(name="vlan120", interface="agg1", vlanid=120, vdom="blue")])
    vdom = PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys1",
                                review_state=PANDecisionReviewState.CONFIRMED)
    parent = PANMigrationDecision("root", "interface", "agg1", "target_interface", value="ae1",
                                  review_state=PANDecisionReviewState.CONFIRMED)
    child = PANMigrationDecision("root", "interface", "vlan120", "target_interface")
    other = PANMigrationDecision("blue", "interface", "vlan120", "target_interface")
    dependencies = dependent_decision_keys(config, PANMigrationDecisionSet((vdom, parent, child, other)))
    assert dependencies[vdom.key] == [child.key]
    assert other.key not in dependencies[parent.key]


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


def test_rule_impact_is_scoped_to_explicit_relationships_and_confirmed_sources():
    config = FGConfig(interfaces=[FGInterface(name="agg1", type="aggregate"),
        FGInterface(name="vlan120", type="vlan", interface="agg1", vlanid=120),
        FGInterface(name="other", type="ethernet")])
    parent = PANMigrationDecision("root", "interface", "agg1", "target_interface", value="ae1",
                                  review_state=PANDecisionReviewState.CONFIRMED)
    child = PANMigrationDecision("root", "interface", "vlan120", "target_interface")
    unrelated = PANMigrationDecision("root", "interface", "other", "target_interface", value="ethernet1/3",
                                     review_state=PANDecisionReviewState.CONFIRMED)
    decisions = PANMigrationDecisionSet((parent, child, unrelated))
    assert rule_affected_decision_keys(config, decisions, MigrationRuleType.PARENT_INTERFACE, parent.key) == [child.key]
    with pytest.raises(ValueError, match="explicit VLAN children"):
        rule_affected_decision_keys(config, decisions, MigrationRuleType.PARENT_INTERFACE, unrelated.key)


def test_repeated_engineer_pattern_is_only_a_suggestion_until_applied():
    names = ["lan1", "lan2", "lan3", "lan4", "lan5"]
    config = FGConfig(interfaces=[FGInterface(name=name) for name in names],
        zones=[FGZone(name="LAN", members=names, explicit_fields={"members"})])
    decisions = []
    for name in names[:3]:
        decisions.append(PANMigrationDecision("root", "interface", name, "target_zone", value="TRUST",
            review_state=PANDecisionReviewState.CONFIRMED, evidence_source="ENGINEER", evidence_type="MANUAL"))
    decisions.extend(PANMigrationDecision("root", "interface", name, "target_zone") for name in names[3:])
    decision_set = PANMigrationDecisionSet(tuple(decisions))
    suggestions = repeated_zone_action_suggestions(config, decision_set)
    assert len(suggestions) == 1 and suggestions[0]["affected"] == names[3:]
    assert all(item.review_state == PANDecisionReviewState.PENDING for item in decision_set.decisions[3:])
    updated = apply_repeated_zone_action(config, decision_set, source_vdom="root", source_zone="LAN",
        value="TRUST", apply_to=suggestions[0]["apply_to"])
    assert all(item.review_state == PANDecisionReviewState.CONFIRMED
               and item.evidence_type == "ENGINEER_REPEATED_ACTION_RULE"
               for item in updated.decisions[3:])
    with pytest.raises(ValueError, match="explicit-member pattern"):
        apply_repeated_zone_action(config, decision_set, source_vdom="root", source_zone="LAN",
            value="TRUST", apply_to=['["root","interface","elsewhere","target_zone"]'])
