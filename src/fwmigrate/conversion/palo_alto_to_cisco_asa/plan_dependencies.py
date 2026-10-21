"""ASA prerequisite and atomic traffic-unit validation."""

from dataclasses import replace


TRAFFIC = {"interface", "static_route", "policy", "default_behavior", "acl_binding", "security_controls", "activation"}


def validate_plan(plan):
    rows = list(plan.items)
    keys = [row.key for row in rows]
    known = set(keys)
    owners = {}
    for row in rows:
        namespace = "object" if row.family in {"address", "address_group", "service", "service_group"} else row.family
        owners.setdefault((namespace, row.target_name.casefold()), []).append(row.key)
    duplicates = {key for values in owners.values() if len(values) > 1 for key in values}
    updated = []
    for row in rows:
        reasons = list(row.blockers)
        if keys.count(row.key) != 1 or row.key in duplicates:
            reasons.append("DUPLICATE_SOURCE_OR_TARGET_IDENTITY")
        if any(dep not in known for dep in row.dependencies):
            reasons.append("PLAN_DEPENDENCY_UNRESOLVED")
        updated.append(replace(row, blockers=tuple(dict.fromkeys(reasons))))
    remaining, done = {row.key: row for row in updated}, set()
    while remaining:
        ready = {key for key, row in remaining.items() if set(row.dependencies) <= done}
        if not ready:
            break
        done.update(ready)
        remaining = {key: row for key, row in remaining.items() if key not in ready}
    updated = [replace(row, blockers=(*row.blockers, "PLAN_DEPENDENCY_CYCLE")) if row.key in remaining else row
               for row in updated]
    changed = True
    while changed:
        blocked = {row.key for row in updated if row.blockers}
        traffic_blocked = any(row.family in TRAFFIC and row.blockers for row in updated)
        next_rows = [replace(row, blockers=("ATOMIC_TRAFFIC_UNIT_BLOCKED" if row.family in TRAFFIC and traffic_blocked
                                             else "PLAN_DEPENDENCY_BLOCKED",))
                     if not row.blockers and (set(row.dependencies) & blocked or row.family in TRAFFIC and traffic_blocked)
                     else row for row in updated]
        changed = next_rows != updated
        updated = next_rows
    return replace(plan, items=tuple(updated))


def ordered_items(plan):
    remaining = [row for row in validate_plan(plan).items if not row.blockers]
    result, done = [], set()
    while remaining:
        ready = sorted((row for row in remaining if set(row.dependencies) <= done), key=lambda row: (row.source_order, row.key))
        if not ready:
            raise ValueError("ASA dependency cycle")
        for row in ready:
            result.append(row)
            done.add(row.key)
            remaining.remove(row)
    return tuple(result)


def assess_render_disposition(plan):
    return {row.key: row.disposition for row in validate_plan(plan).items}
