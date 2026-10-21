"""Validate dependencies and propagate blocked Junos plan items."""

from dataclasses import replace


def validate_plan(plan):
    rows = list(plan.items)
    keys = [row.key for row in rows]
    duplicate_keys = {key for key in keys if keys.count(key) > 1}
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
    updated = []
    for row in rows:
        blockers = list(row.blockers)
        if row.key in duplicate_keys:
            blockers.append("DUPLICATE_PLAN_IDENTITY")
        if row.key in duplicate_names:
            blockers.append("DUPLICATE_TARGET_OBJECT_NAME")
        if any(dep not in known for dep in row.dependencies):
            blockers.append("PLAN_DEPENDENCY_UNRESOLVED")
        updated.append(replace(row, blockers=tuple(dict.fromkeys(blockers))))
    by_key = {row.key: row for row in updated}
    changed = True
    while changed:
        changed = False
        for index, row in enumerate(updated):
            if not row.blockers and any(by_key.get(dep) and by_key[dep].blockers for dep in row.dependencies):
                updated[index] = replace(row, blockers=("PLAN_DEPENDENCY_BLOCKED",))
                by_key[row.key] = updated[index]
                changed = True
    return replace(plan, items=tuple(updated))


def ordered_items(plan):
    plan = validate_plan(plan)
    by_key = {row.key: row for row in plan.items}
    out, done = [], set()
    remaining = [row for row in plan.items if not row.blockers]
    while remaining:
        ready = [row for row in remaining if set(row.dependencies) <= done]
        if not ready:
            break
        ready.sort(key=lambda row: (row.source_order, row.key))
        for row in ready:
            out.append(row)
            done.add(row.key)
            remaining.remove(row)
    return tuple(out)


def assess_render_disposition(plan):
    plan = validate_plan(plan)
    return {row.key: ("BLOCK" if row.blockers else row.target_disposition or "CREATE") for row in plan.items}
