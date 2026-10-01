from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionMode, PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.review_workflow import build_review_workflow
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig


def test_conflicting_groups_show_all_owners_and_reserved_candidates_are_not_actionable():
    from fwmigrate.conversion.fortigate_to_palo_alto.application.review import decision_evidence
    from fwmigrate.conversion.fortigate_to_palo_alto.target_validation import validate_against_target

    config = FGConfig()
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision(vdom, "interface", "port1", "target_interface",
        value="ethernet1/1", review_state=PANDecisionReviewState.CONFIRMED) for vdom in ("root", "branch")))
    findings = validate_against_target(config, decisions, None, None)
    workflow = build_review_workflow(config, decisions, candidates={}, context={},
        decision_evidence=decision_evidence(decisions, findings), target_warnings={}, target_findings=findings)
    assert all(group['queue'] == 'CONFLICT' and len(group['conflicts'][0]['evidence']) == 2
               and 'root / port1' in group['next_action'] and 'branch / port1' in group['next_action']
               for group in workflow['review_groups'])
    pending = PANMigrationDecision("root", "interface", "port2", "target_interface",
        suggested_value="ethernet1/1", mode=PANDecisionMode.SUGGESTED)
    workflow = build_review_workflow(config, PANMigrationDecisionSet((pending,)), context={}, decision_evidence={}, target_warnings={},
        candidates={pending.key: [{'value': 'ethernet1/1', 'class': 'STRONG', 'available': False}]})
    assert workflow['review_groups'][0]['queue'] == 'NEEDS_INPUT'


def test_review_workflow_groups_decisions_classifies_queues_and_orders_vdom_first():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="vlan", interface="agg1")])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "lan", "target_interface"),
        PANMigrationDecision("root", "interface", "lan", "target_zone", suggested_value="TRUST", mode=PANDecisionMode.SUGGESTED),
        PANMigrationDecision("root", "interface", "agg1", "target_interface", suggested_value="ae1", mode=PANDecisionMode.SUGGESTED),
        PANMigrationDecision("root", "vdom", "root", "vsys"),
        PANMigrationDecision("root", "interface", "auto0", "target_interface", value="ethernet1/1", mode=PANDecisionMode.AUTO),
    ))
    target_key = decisions.decisions[0].key
    workflow = build_review_workflow(config, decisions, candidates={target_key: [{"value": "ethernet1/2", "class": "POSSIBLE"}]},
        context={"root": {"source_type": "vlan"}}, decision_evidence={}, target_warnings={})
    groups = workflow["review_groups"]
    assert groups[0]["source_kind"] == "vdom"
    lan = next(item for item in groups if item["source_name"] == "lan")
    assert len(lan["decision_keys"]) == 2
    assert lan["queue"] == "CHOOSE_CANDIDATE"
    assert workflow["review_summary"] == {
        "auto_resolved": 1, "ready_to_confirm": 2, "choose_candidate": 1,
        "needs_input": 1, "conflicts": 0, "confirmed": 0,
    }


def test_review_workflow_groups_parent_choice_with_affected_vlan_children():
    config = FGConfig(interfaces=[FGInterface(name="agg1", type="aggregate"),
        FGInterface(name="vlan100", type="vlan", interface="agg1", vlanid=100),
        FGInterface(name="vlan200", type="vlan", interface="agg1", vlanid=200)])
    decision = PANMigrationDecision("root", "interface", "agg1", "target_interface")
    workflow = build_review_workflow(config, PANMigrationDecisionSet((decision,)),
        candidates={decision.key: [{"value": "ae1", "class": "STRONG"}]},
        context={}, decision_evidence={}, target_warnings={})
    assert workflow["architecture_questions"] == [{"type": "AGGREGATE_MAPPING", "source_vdom": "root",
        "source_name": "agg1", "decision_key": decision.key, "candidates": ["ae1"],
        "affected_count": 2, "affected": ["vlan100", "vlan200"]}]
