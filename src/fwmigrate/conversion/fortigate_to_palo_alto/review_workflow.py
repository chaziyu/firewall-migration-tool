"""Read-only work queues derived from existing FortiGate-to-PAN decisions."""

from collections import Counter

from .decisions import PANDecisionMode, PANDecisionReviewState
from .decision_propagation import (
    dependent_decision_keys, repeated_zone_action_suggestions, zone_member_decision_keys,
)


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
    architecture_questions = []
    interfaces = {(item.vdom or "root", item.name): item for item in getattr(config, "interfaces", ())}
    for group in result:
        pending = [item for item in group["decisions"] if item["mode"] != "UNSUPPORTED"
                   and item["review_state"] != PANDecisionReviewState.CONFIRMED]
        if group["source_kind"] == "vdom" and pending:
            architecture_questions.append({"type": "VDOM_CONTEXT", "source_vdom": group["source_vdom"],
                "source_name": group["source_name"], "fields": [
                    {"key": item["key"], "target_field": item["target_field"],
                     "suggested_value": item.get("suggested_value")} for item in pending]})
        elif group["source_kind"] == "zone" and pending:
            decision = next((item for item in pending if item["target_field"] == "target_zone"), None)
            if decision:
                choices = list(dict.fromkeys([decision.get("suggested_value"), *[
                    item.get("value") for item in (candidates or {}).get(decision["key"], ())]]))
                architecture_questions.append({"type": "ZONE_MAPPING", "source_vdom": group["source_vdom"],
                    "source_name": group["source_name"], "decision_key": decision["key"],
                    "candidates": [item for item in choices if item]})
        source = interfaces.get((group["source_vdom"], group["source_name"]))
        if group["source_kind"] != "interface" or source is None or (source.type or "").casefold() != "aggregate":
            continue
        key = next((item["key"] for item in group["decisions"] if item["target_field"] == "target_interface"), None)
        options = (candidates or {}).get(key, ())
        matches = [item for item in options if item.get("class") == "STRONG"]
        children = [item for item in getattr(config, "interfaces", ())
                    if (item.vdom or "root") == group["source_vdom"] and item.interface == source.name
                    and item.vlanid is not None]
        parent_pending = any(item["key"] == key and item["review_state"] != PANDecisionReviewState.CONFIRMED
                             for item in group["decisions"])
        if key and parent_pending and matches and children:
            architecture_questions.append({"type": "AGGREGATE_MAPPING", "source_vdom": group["source_vdom"],
                "source_name": source.name, "decision_key": key,
                "candidates": [item["value"] for item in matches], "affected_count": len(children),
                "affected": [item.name for item in children]})
    summary = {
        "auto_resolved": sum(item.mode == PANDecisionMode.AUTO for item in decisions.decisions),
        "ready_to_confirm": queues["READY_TO_CONFIRM"],
        "choose_candidate": queues["CHOOSE_CANDIDATE"],
        "needs_input": queues["NEEDS_INPUT"],
        "conflicts": queues["CONFLICT"],
        "confirmed": sum(item.review_state == PANDecisionReviewState.CONFIRMED for item in decisions.decisions),
    }
    return {"review_summary": summary, "review_groups": result,
            "architecture_questions": architecture_questions,
            "rule_suggestions": repeated_zone_action_suggestions(config, decisions)}
