"""Bind source, target intent, exact configuration and selected dependencies."""
import time
from graphlib import CycleError, TopologicalSorter

from ..models import digest

PAIR = {"source_vendor": "palo_alto", "target_vendor": "fortigate"}
APPROVAL_TTL = 24 * 60 * 60


def build_deterministic_draft(plan, rendered, requirements, options, source_digest, target_digest=None):
    context = {**PAIR, "source_digest": source_digest, "target_digest": target_digest,
               "options": options.to_dict(), "workflow_mode": "DESTINATION_AWARE" if target_digest else "OFFLINE_EXPORT"}
    body = {"envelope_type": "fg_migration_draft_v1", "schema_version": 1, "context": context,
            "configuration": rendered.report["items"], "decisions": requirements["decisions"], "findings": list(plan.findings),
            "readiness": {"deployment": {"eligible": False, "reason": "FortiGate export only."}}}
    body["digest"] = digest(body)
    return body


def approve_draft(draft, selected):
    if not isinstance(selected, list) or not selected or any(not isinstance(key, str) for key in selected) or len(set(selected)) != len(selected):
        raise ValueError("Select unique configuration items for approval")
    rows = {row["key"]: row for row in draft["configuration"]}
    expanded = set()
    try:
        tuple(TopologicalSorter({key: row["dependencies"] for key, row in rows.items()}).static_order())
    except CycleError as exc:
        raise ValueError("Invalid approval dependency") from exc
    pending = list(selected)
    while pending:
        key = pending.pop()
        if key not in rows:
            raise ValueError("Invalid approval dependency")
        if key in expanded:
            continue
        row = rows[key]
        if row["blocking_reasons"] or row["render_disposition"] == "BLOCK":
            raise ValueError("Blocked or unsupported configuration cannot be approved")
        pending.extend(row["dependencies"])
        expanded.add(key)
    return {"envelope_type": "fg_design_approval_v1", "context": draft["context"], "draft_digest": draft["digest"],
            "configuration": {key: digest(rows[key]) for key in sorted(expanded)}, "expires_at": time.time() + APPROVAL_TTL}


def validate_approval(approval, draft):
    if (approval.get("envelope_type") != "fg_design_approval_v1" or approval.get("context") != draft["context"]
            or approval.get("draft_digest") != draft["digest"] or type(approval.get("expires_at")) not in {int, float}
            or not time.time() < approval["expires_at"] < time.time() + APPROVAL_TTL + 60):
        raise ValueError("Design approval is expired or belongs to a different migration context")
    rows = {row["key"]: row for row in draft["configuration"]}
    selected = approval.get("configuration")
    if not isinstance(selected, dict) or not selected:
        raise ValueError("Design approval contains no selected configuration")
    for key, value in selected.items():
        row = rows.get(key)
        if row is None or digest(row) != value or row["blocking_reasons"] or row["render_disposition"] == "BLOCK" or any(parent not in selected for parent in row["dependencies"]):
            raise ValueError("Approved configuration or dependencies changed")
    return set(selected)
