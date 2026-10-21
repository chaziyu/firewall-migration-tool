"""Native scoped PAN inventory accounting for Cisco FTD migration."""

from collections import Counter

from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity

from ..plan_dependencies import dispositions


def build_coverage(plan, source_inventory=(), derived=None, *, approved_items=None):
    state = dispositions(plan)
    planned = {}
    for row in plan.items:
        key = (row.source_scope, row.source_path, row.source_name)
        planned.setdefault(key, []).append(row.key)
    counts = Counter()
    for row in source_inventory:
        scope = pan_scope_identity(row.scope) if row.scope else "unscoped"
        keys = planned.get((scope, row.source_path, row.name or "(unnamed)"), ())
        if not keys or any(state[key] == "BLOCK" for key in keys):
            counts["manual_records"] += 1
        elif approved_items is not None and any(key not in approved_items for key in keys):
            counts["unapproved_records"] += 1
        else:
            counts["planned_records"] += 1
    return {
        "source_records": len(source_inventory),
        **{name: counts[name] for name in ("planned_records", "manual_records", "unapproved_records")},
    }
