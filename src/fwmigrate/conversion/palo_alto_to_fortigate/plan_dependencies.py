"""Dependency order and blockers for FortiOS planned items."""
from graphlib import CycleError, TopologicalSorter


def build_plan_dependency_index(plan):
    return {item.key: item.dependencies for item in plan.items}


def ordered_items(plan):
    by_key = {item.key: item for item in plan.items}
    if any(parent not in by_key for item in plan.items for parent in item.dependencies):
        raise ValueError("Migration dependency is missing")
    try:
        return tuple(by_key[key] for key in TopologicalSorter(build_plan_dependency_index(plan)).static_order())
    except CycleError as exc:
        raise ValueError("Migration dependency cycle") from exc


def render_blockers(plan, approved=None):
    blockers = {}
    try:
        ordered = ordered_items(plan)
    except ValueError:
        return {item.key: (*item.reasons, *plan.findings, "Invalid migration dependency graph.") for item in plan.items}
    for item in ordered:
        reasons = list(item.reasons) + list(plan.findings)
        if item.disposition == "BLOCK" and not reasons:
            reasons.append("Unsupported configuration cannot satisfy dependencies.")
        if approved is not None and item.key not in approved:
            reasons.append("Not selected for engineer approval.")
        for parent in item.dependencies:
            if blockers[parent]:
                reasons.append("Blocked dependency: " + parent)
        blockers[item.key] = tuple(dict.fromkeys(reasons))
    return blockers
