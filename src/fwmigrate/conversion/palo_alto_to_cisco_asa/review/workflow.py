"""Review-safe report projection."""

from dataclasses import asdict

from ..plan_dependencies import assess_render_disposition, validate_plan
from ..recommendations.support_guidance import support_guidance


def build_review_report(plan, *, approved_items=None):
    plan = validate_plan(plan)
    dispositions = assess_render_disposition(plan)
    approved = None if approved_items is None else set(approved_items)
    items = []
    for row in plan.items:
        disposition = dispositions[row.key]
        items.append({**asdict(row), "settings": dict(row.settings), "dependencies": list(row.dependencies),
                      "blockers": list(row.blockers), "guidance": list(support_guidance(row.blockers)),
                      "render_disposition": ("NOT_APPROVED" if approved is not None and row.key not in approved
                                             and disposition in {"CREATE", "REUSE"} else disposition)})
    return {"pair_id": "palo_alto_to_cisco_asa", "source_scope": plan.source_scope,
            "target_context": plan.target_context, "target_version": plan.target_version,
            "plan_status": ("BLOCKED" if not any(row["render_disposition"] in {"CREATE", "REUSE"} for row in items)
                            else "PARTIAL" if any(row["render_disposition"] in {"BLOCK", "NOT_APPROVED"} for row in items)
                            else "READY_FOR_REVIEW"),
            "renderable_item_count": sum(row["render_disposition"] == "CREATE" for row in items),
            "reused_item_count": sum(row["render_disposition"] == "REUSE" for row in items),
            "blocked_item_count": sum(row["render_disposition"] == "BLOCK" for row in items),
            "items": items, "findings": list(plan.findings), "deployment_available": False,
            "destination_verified": False}
