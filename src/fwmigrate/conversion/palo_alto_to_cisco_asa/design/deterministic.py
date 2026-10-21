"""Deterministic source-bound review and exact selection approval."""

from dataclasses import asdict
import hashlib
import json
import math
import time

from ..options import ASAMigrationOptions
from ..plan_dependencies import validate_plan
from ..rendering.renderer import ASACLIRenderer


PAIR = {"pair_id": "palo_alto_to_cisco_asa", "source_vendor": "palo_alto", "target_vendor": "cisco_asa"}
DRAFT_TYPE = "palo_alto_to_cisco_asa_design_v1"
APPROVAL_TYPE = "palo_alto_to_cisco_asa_approval_v1"


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def build_draft(plan, source_digest, options, target_evidence=None):
    parsed = options if isinstance(options, ASAMigrationOptions) else ASAMigrationOptions(**(options or {}))
    plan = validate_plan(plan)
    context = {**PAIR, "source_digest": source_digest, "options": parsed.to_dict(),
               "target_digest": target_evidence.digest if target_evidence else None,
               "target_context": {"context": target_evidence.context, "version": target_evidence.version,
                                 "mode": target_evidence.mode,
                                 "complete_families": sorted(target_evidence.complete_families)} if target_evidence else None}
    return {"envelope_type": DRAFT_TYPE, **context, "context_digest": _digest(context),
            "digest": _digest({"context": context, "plan": asdict(plan)}),
            "items": [asdict(row) for row in plan.items], "findings": list(plan.findings)}


def _selected(plan, selected_items):
    plan = validate_plan(plan)
    if not isinstance(selected_items, list) or not selected_items or any(not isinstance(key, str) for key in selected_items):
        raise ValueError("Select at least one ready migration item")
    if len(selected_items) != len(set(selected_items)):
        raise ValueError("Selection contains duplicate item keys")
    by_key = {row.key: row for row in plan.items}
    if set(selected_items) - set(by_key):
        raise ValueError("Selection contains an unknown migration item")
    expanded = set(selected_items)
    while True:
        dependencies = {dep for key in expanded for dep in by_key[key].dependencies}
        if not dependencies <= set(by_key):
            raise ValueError("A selected dependency is unavailable")
        next_items = expanded | dependencies
        groups = {by_key[key].approval_group for key in next_items if by_key[key].approval_group}
        next_items.update(row.key for row in plan.items if row.approval_group in groups)
        if next_items == expanded:
            break
        expanded = next_items
    if any(by_key[key].blockers for key in expanded):
        raise ValueError("A selected operation or dependency is blocked")
    if expanded != set(selected_items):
        raise ValueError("Selection is missing dependencies or the atomic traffic unit; preview the complete selection")
    selected = [row for row in plan.items if row.key in expanded]
    renderer = ASACLIRenderer().render(type(plan)(plan.source_scope, plan.target_context, plan.target_version, tuple(selected), plan.findings))
    if renderer.blocked_items:
        raise ValueError("Selected operations cannot be rendered safely")
    return [row.key for row in selected], renderer


def approve_draft(plan, draft, selected_items, target_evidence=None):
    current = build_draft(plan, draft.get("source_digest"), draft.get("options", {}), target_evidence)
    if (draft.get("envelope_type") != DRAFT_TYPE or any(draft.get(key) != value for key, value in PAIR.items())
            or draft.get("digest") != current["digest"] or draft.get("context_digest") != current["context_digest"]):
        raise ValueError("Draft changed; prepare and review the current migration again")
    selected, rendered = _selected(plan, selected_items)
    return {"envelope_type": APPROVAL_TYPE, **PAIR, "source_digest": current["source_digest"],
            "target_digest": current["target_digest"],
            "draft_digest": current["digest"], "context_digest": current["context_digest"],
            "selected_items": selected, "command_count": rendered.command_count,
            "command_sha256": rendered.command_sha256, "expires_at": time.time() + 1200}


def validate_approval(plan, draft, approval, target_evidence=None):
    if (not isinstance(approval, dict) or type(approval.get("expires_at")) not in {int, float}
            or not math.isfinite(approval["expires_at"]) or time.time() >= approval["expires_at"]):
        raise ValueError("A current unexpired design approval is required")
    if (approval.get("envelope_type") != APPROVAL_TYPE or any(approval.get(key) != value for key, value in PAIR.items())
            or approval.get("source_digest") != draft.get("source_digest")
            or approval.get("target_digest") != draft.get("target_digest")
            or approval.get("draft_digest") != draft.get("digest")
            or approval.get("context_digest") != draft.get("context_digest")):
        raise ValueError("Approval belongs to a different source or design")
    current = build_draft(plan, draft.get("source_digest"), draft.get("options", {}), target_evidence)
    if current.get("digest") != draft.get("digest"):
        raise ValueError("Current source or target evidence differs from the reviewed design")
    selected, rendered = _selected(plan, approval.get("selected_items"))
    if (selected != approval.get("selected_items") or rendered.command_count != approval.get("command_count")
            or rendered.command_sha256 != approval.get("command_sha256")):
        raise ValueError("Approved operations changed; review the current migration again")
    return selected, rendered


def export_decisions(source_digest, options):
    parsed = options if isinstance(options, ASAMigrationOptions) else ASAMigrationOptions(**(options or {}))
    return {"format_version": 1, **PAIR, "source_digest": source_digest, "options": parsed.to_dict()}


def import_decisions(document, source_digest):
    if (not isinstance(document, dict) or document.get("format_version") != 1
            or document.get("source_digest") != source_digest
            or any(document.get(key) != value for key, value in PAIR.items())):
        raise ValueError("Decision document belongs to a different source or migration pair")
    return export_decisions(source_digest, document.get("options", {}))["options"]
