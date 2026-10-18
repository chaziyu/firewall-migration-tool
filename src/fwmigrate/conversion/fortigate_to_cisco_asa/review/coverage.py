"""Source inventory accounting for this directional migration pair."""

from collections import Counter, defaultdict

from ..validation import dispositions


_SECTION_FAMILIES = {
    "firewall ippool": ("nat_pool",),
    "system interface": ("interface",),
    "firewall address": ("address",),
    "firewall addrgrp": ("address_group",),
    "firewall service custom": ("service", "service_group"),
    "firewall service group": ("service_group",),
    "firewall policy": ("policy", "nat"),
    "router static": ("static_route",),
    "firewall schedule recurring": ("schedule",),
    "firewall schedule onetime": ("schedule",),
    "firewall vip": ("vip",),
}


def build_coverage(plan, source_inventory, derived, *, approved_items=None):
    """Count source records separately from expanded plan items and approval."""
    state = dispositions(plan)
    selected = None if approved_items is None else set(approved_items)
    service_sources = {
        (row.vdom, row.name): row.source_name or row.name
        for row in derived.services.services
    }
    index = defaultdict(list)
    for item in plan.items:
        name = item.source_name
        settings = dict(item.settings)
        if item.family in {"service", "service_group"}:
            name = service_sources.get((item.source_vdom, name), name)
        if (
            item.family in {"policy", "source_nat"}
            and settings.get(
                "policy_id",
            )
            is not None
        ):
            name = str(settings["policy_id"])
        index[item.source_vdom, item.family, name].append(item)
    rows = []
    for record in source_inventory:
        if plan.source_vdom is not None and record.vdom not in {None, plan.source_vdom}:
            continue
        matches = [
            item
            for family in _SECTION_FAMILIES.get(record.source_path, ())
            for item in index[record.vdom, family, record.object_name]
        ]
        statuses = []
        for item in matches:
            if state[item.key] == "BLOCK":
                statuses.append("MANUAL" if item.blockers else "DEPENDENCY_BLOCKED")
            elif selected is None or item.key not in selected:
                statuses.append("PENDING")
            else:
                statuses.append("REUSED" if state[item.key] == "REUSE" else "RENDERED")
        status = next(
            (
                value
                for value in ("MANUAL", "DEPENDENCY_BLOCKED", "PENDING")
                if value in statuses
            ),
            "RENDERED" if "RENDERED" in statuses else "REUSED",
        )
        if not matches:
            status = "MANUAL"
        rows.append(
            {
                "source_vdom": record.vdom,
                "source_scope": record.cli_scope,
                "source_path": record.source_path,
                "source_name": record.object_name,
                "parent_objects": list(record.parent_objects),
                "source_line": record.start_line_number,
                "plan_item_keys": [item.key for item in matches],
                "status": status,
            }
        )
    return {
        "source_record_count": len(rows),
        "status_counts": dict(Counter(row["status"] for row in rows)),
        "records": rows,
        "inventory_available": bool(source_inventory),
        "export_is_complete_migration": False,
        "note": "Coverage counts source records, including repeated edits. An approved subset is not a complete migration.",
    }
