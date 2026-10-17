"""Pair-specific review projection for the Check Point plan."""

from dataclasses import asdict


def build_review_report(plan):
    return {
        "pair_id": "fortigate_to_checkpoint",
        "source_vdom": plan.source_vdom,
        "items": [{**asdict(item), "settings": dict(item.settings),
                   "dependencies": list(item.dependencies), "blockers": list(item.blockers)}
                  for item in plan.items],
        "decisions": [asdict(item) for item in plan.decisions],
        "findings": [asdict(item) for item in plan.findings],
        "offline_export": True,
        "destination_snapshot_compared": False,
        "deployment_available": False,
    }
