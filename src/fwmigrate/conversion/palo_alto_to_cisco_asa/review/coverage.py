"""Source inventory accounting for review reports."""

from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity

def build_coverage(plan, source_inventory=()):
    planned = {(row.source_scope, row.source_path, row.source_name) for row in plan.items}
    counts = {"source_records": len(source_inventory), "planned_records": 0, "manual_records": 0}
    for row in source_inventory:
        scope = pan_scope_identity(row.scope) if row.scope else "unscoped"
        if (scope, row.source_path, row.name or "(unnamed)") in planned:
            counts["planned_records"] += 1
        else:
            counts["manual_records"] += 1
    return counts
