"""Validate dependencies and propagate blocked Junos plan items."""

from collections import Counter, defaultdict, deque
from dataclasses import replace
from graphlib import CycleError, TopologicalSorter

from .models import SRXMigrationPlan


RENDER_FAMILY_ORDER = {"address": 0, "address_group": 1, "service": 2, "service_group": 3,
                       "interface": 4, "zone": 5, "static_route": 6, "policy": 7}


def validate_plan(plan: SRXMigrationPlan) -> SRXMigrationPlan:
    rows = list(plan.items)
    keys = Counter(row.key for row in rows)
    duplicate_keys = {key for key, count in keys.items() if count > 1}
    duplicate_names = {}
    for row in rows:
        if row.family == "policy":
            settings = dict(row.settings)
            duplicate_names.setdefault((row.family, row.target_name.casefold(),
                                        settings.get("from_zone"), settings.get("to_zone")), []).append(row.key)
        elif row.family not in {"inactive_policy", "nat", "inactive_nat"}:
            duplicate_names.setdefault((row.family, row.target_name.casefold()), []).append(row.key)
    duplicate_names = {key for owners in duplicate_names.values() if len(owners) > 1 for key in owners}
    known = set(keys)
    graph = TopologicalSorter({row.key: set(row.dependencies) & known for row in rows})
    try:
        graph.prepare()
    except CycleError:
        # graphlib still permits draining nodes independent of the cycle.
        pass
    ordered = set()
    while graph.is_active():
        ready = graph.get_ready()
        if not ready:
            break
        ordered.update(ready)
        graph.done(*ready)
    # Includes consumers whose prerequisites cannot be ordered because of a cycle.
    cyclic = known - ordered
    dependents = defaultdict(set)
    updated = []
    for row in rows:
        blockers = list(row.blockers)
        if row.key in duplicate_keys:
            blockers.append("DUPLICATE_PLAN_IDENTITY")
        if row.key in duplicate_names:
            blockers.append("DUPLICATE_TARGET_OBJECT_NAME")
        if any(dep not in known for dep in row.dependencies):
            blockers.append("PLAN_DEPENDENCY_UNRESOLVED")
        if row.key in cyclic:
            blockers.append("PLAN_DEPENDENCY_CYCLE")
        if row.family not in RENDER_FAMILY_ORDER:
            blockers.append("RENDER_FAMILY_UNSUPPORTED")
        if row.target_disposition == "BLOCK":
            blockers.append("TARGET_DISPOSITION_BLOCKED")
        elif row.target_disposition not in {None, "CREATE", "REUSE"}:
            blockers.append("TARGET_DISPOSITION_UNSUPPORTED")
        for dependency in row.dependencies:
            dependents[dependency].add(row.key)
        updated.append(replace(row, blockers=tuple(dict.fromkeys(blockers))))
    blocked = {row.key for row in updated if row.blockers}
    pending = deque(blocked)
    while pending:
        for key in dependents[pending.popleft()] - blocked:
            blocked.add(key)
            pending.append(key)
    return replace(plan, items=tuple(
        replace(row, blockers=("PLAN_DEPENDENCY_BLOCKED",)) if row.key in blocked and not row.blockers else row
        for row in updated
    ))


def assess_render_disposition(plan):
    plan = validate_plan(plan)
    return {row.key: ("BLOCK" if row.blockers else row.target_disposition or "CREATE") for row in plan.items}
