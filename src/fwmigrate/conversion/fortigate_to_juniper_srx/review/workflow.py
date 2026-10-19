"""Review-safe report projections for SRX migration plans."""

from dataclasses import asdict

from ..plan_dependencies import assess_render_disposition, validate_plan
from ..recommendations.support_guidance import support_guidance


def build_review_report(plan, *, approved_items=None):
    plan = validate_plan(plan)
    dispositions = assess_render_disposition(plan)
    selected = None if approved_items is None else set(approved_items)
    items = []
    for item in plan.items:
        blockers = list(item.blockers)
        if dispositions[item.key] == "BLOCK" and not blockers:
            blockers.append("DEPENDENCY_BLOCKED")
        items.append({
            **asdict(item),
            "settings": dict(item.settings),
            "dependencies": list(item.dependencies),
            "decision_keys": list(item.decision_keys),
            "blockers": blockers,
            "guidance": list(support_guidance(blockers)),
            "render_disposition": "NOT_APPROVED" if selected is not None
            and item.key not in selected and dispositions[item.key] in {"CREATE", "REUSE"}
            else dispositions[item.key],
        })
    findings = [asdict(finding) for finding in plan.findings]
    renderable_count = sum(item["render_disposition"] == "CREATE" for item in items)
    reused_count = sum(item["render_disposition"] == "REUSE" for item in items)
    blocked_count = sum(item["render_disposition"] == "BLOCK" for item in items)
    omitted_count = sum(item["render_disposition"] == "NOT_APPROVED" for item in items)
    blocking_findings = any(finding.blocking for finding in plan.findings)
    if (renderable_count or reused_count) and (blocked_count or omitted_count or blocking_findings):
        status = "READY_WITH_MANUAL_WORK"
    elif renderable_count or reused_count:
        status = "READY_FOR_REVIEW"
    else:
        status = "BLOCKED"
    return {
        "pair_id": "fortigate_to_juniper_srx",
        "source_vdom": plan.source_vdom,
        "target_context": plan.target_context,
        "target_version": plan.target_version,
        "target_mode": plan.target_mode,
        "routing_table": plan.routing_table,
        "plan_status": status,
        "renderable_item_count": renderable_count,
        "reused_item_count": reused_count,
        "blocked_item_count": blocked_count,
        "not_approved_item_count": omitted_count,
        "items": items,
        "findings": findings,
        "deployment_available": False,
        "destination_verified": False,
    }
