"""Read-only work queues derived from existing FortiGate-to-PAN decisions."""

from collections import Counter

from .decisions import PANDecisionMode, PANDecisionReviewState
from .decision_propagation import dependent_decision_keys, zone_member_decision_keys


def _queue(decision, candidates, evidence):
    if evidence == "CONFLICT":
        return "CONFLICT"
    if decision.mode == PANDecisionMode.AUTO:
        return "COMPLETE"
    if decision.review_state == PANDecisionReviewState.CONFIRMED:
        return "COMPLETE"
    if decision.mode == PANDecisionMode.SUGGESTED and decision.suggested_value:
        return "READY_TO_CONFIRM"
    if candidates:
        return "CHOOSE_CANDIDATE"
    return "NEEDS_INPUT"


def build_review_workflow(config, decisions, *, candidates, context, decision_evidence, target_warnings):
    dependencies = dependent_decision_keys(config, decisions)
    groups = {}
    queues = Counter()
    for decision in decisions.decisions:
        key = decision.key
        evidence = decision_evidence.get(key, "SOURCE")
        options = candidates.get(key, ())
        queue = _queue(decision, options, evidence)
        queues[queue] += 1
        identity = (decision.source_vdom, decision.source_kind, decision.source_name)
        group = groups.setdefault(identity, {"source_vdom": decision.source_vdom,
            "source_kind": decision.source_kind, "source_name": decision.source_name,
            "decision_keys": [], "decisions": [], "suggestions": {}, "candidates": {},
            "source_evidence": {}, "affected_count": 0, "dependent_decision_count": 0,
            "next_action": None, "queues": []})
        item = decision.to_dict()
        group["decision_keys"].append(key)
        group["decisions"].append(item)
        if decision.suggested_value:
            group["suggestions"][key] = decision.suggested_value
        if options:
            group["candidates"][key] = list(options)
        facts = context.get(key, {})
        group["source_evidence"].update({name: value for name, value in facts.items() if name.startswith("source_")})
        group["affected_count"] = max(group["affected_count"], decision.affected_count)
        group["dependent_decision_count"] += len(dependencies.get(key, ()))
        group["queues"].append(queue)
        group["next_action"] = group["next_action"] or facts.get("next_action") or target_warnings.get(key)
        if decision.source_kind == "zone" and decision.target_field == "target_zone" and decision.review_state == PANDecisionReviewState.CONFIRMED:
            apply_keys = zone_member_decision_keys(config, decisions, key)
            if apply_keys:
                group.setdefault("actions", []).append({"type": "APPLY_ZONE_TO_MEMBERS", "source_key": key,
                    "value": decision.value, "apply_to": apply_keys})

    rank = {"vdom": 0, "interface": 1, "zone": 3}
    def group_order(group):
        kind = group["source_kind"]
        source_type = str(group["source_evidence"].get("source_type", "")).casefold()
        if source_type in {"physical", "ethernet", "aggregate"}:
            interface_rank = 1
        elif source_type == "vlan" or group["source_evidence"].get("source_parent"):
            interface_rank = 2
        else:
            interface_rank = 4
        return (rank.get(kind, 4) if kind != "interface" else interface_rank,
                group["source_vdom"].casefold(), group["source_name"].casefold())

    result = []
    for group in groups.values():
        priority = ("CONFLICT", "CHOOSE_CANDIDATE", "READY_TO_CONFIRM", "NEEDS_INPUT", "COMPLETE")
        group["queue"] = next((queue for queue in priority if queue in group["queues"]), "COMPLETE")
        group.pop("queues")
        result.append(group)
    result.sort(key=group_order)
    summary = {
        "auto_resolved": sum(item.mode == PANDecisionMode.AUTO for item in decisions.decisions),
        "ready_to_confirm": queues["READY_TO_CONFIRM"],
        "choose_candidate": queues["CHOOSE_CANDIDATE"],
        "needs_input": queues["NEEDS_INPUT"],
        "conflicts": queues["CONFLICT"],
        "confirmed": sum(item.review_state == PANDecisionReviewState.CONFIRMED for item in decisions.decisions),
    }
    return {"review_summary": summary, "review_groups": result}
