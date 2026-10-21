"""Source inventory accounting for review reports."""


def build_coverage(plan, source_inventory=()):
    planned = {(row.source_path, row.source_name) for row in plan.items}
    counts = {"source_records": len(source_inventory), "planned_records": 0, "manual_records": 0}
    for row in source_inventory:
        if (row.source_path, row.name or "(unnamed)") in planned:
            counts["planned_records"] += 1
        else:
            counts["manual_records"] += 1
    return counts
