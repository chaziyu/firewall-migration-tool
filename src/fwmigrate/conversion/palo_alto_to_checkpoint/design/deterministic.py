"""Bind Check Point approvals to source, options, dependencies, and exact files."""

from dataclasses import asdict
import hashlib
import json
import math
import time
import uuid

from ..plan_dependencies import dispositions
from ..rendering.management import CPManagementRenderer


PAIR = {"pair_id": "palo_alto_to_checkpoint", "source_vendor": "palo_alto", "target_vendor": "checkpoint"}
DRAFT_TYPE = "palo_alto_to_checkpoint_draft_v1"
APPROVAL_TYPE = "palo_alto_to_checkpoint_approval_v1"
ARTIFACT_TYPE = "palo_alto_to_checkpoint_artifact_v1"
APPROVAL_TTL = 1200


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_draft(plan, options, source_digest, target_digest=None):
    content = {
        **PAIR,
        "pair": PAIR,
        "source_digest": source_digest,
        "target_digest": target_digest,
        "options": options.to_dict(),
        "plan": {"source_scope": plan.source_scope,
                 "items": [asdict(item) for item in plan.items],
                 "decisions": [asdict(item) for item in plan.decisions],
                 "findings": [asdict(item) for item in plan.findings]},
    }
    content["digest"] = digest(content)
    content["envelope_type"] = DRAFT_TYPE
    return content


def _selected(plan, selected_items):
    if (not isinstance(selected_items, list) or not selected_items
            or any(not isinstance(key, str) for key in selected_items)
            or len(selected_items) != len(set(selected_items))):
        raise ValueError("Select at least one current Check Point plan item")
    by_key = {item.key: item for item in plan.items}
    state = dispositions(plan)
    pending, chosen = list(selected_items), set()
    while pending:
        key = pending.pop()
        item = by_key.get(key)
        if item is None or state.get(key) not in {"CREATE", "REUSE"}:
            raise ValueError("Check Point approval contains an unknown or blocked item")
        if key in chosen:
            continue
        chosen.add(key)
        pending.extend(item.dependencies)
    if chosen != set(selected_items):
        raise ValueError("Preview and select every dependency before approval")
    return sorted(chosen)


def _draft_is_current(draft):
    if not isinstance(draft, dict) or draft.get("envelope_type") != DRAFT_TYPE:
        return False
    body = {key: value for key, value in draft.items()
            if key not in {"digest", "envelope_type", "signature"}}
    return draft.get("digest") == digest(body) and all(draft.get(key) == value for key, value in PAIR.items())


def approve_draft(plan, draft, selected_items):
    if not _draft_is_current(draft):
        raise ValueError("Check Point draft changed; prepare the current design again")
    if any(row.blocking for row in plan.findings):
        raise ValueError("Blocking source findings must be resolved before approval")
    selected = _selected(plan, selected_items)
    rendered = CPManagementRenderer().render(plan, approved_items=selected)
    return {
        "envelope_type": APPROVAL_TYPE,
        **PAIR,
        "source_digest": draft["source_digest"],
        "target_digest": draft.get("target_digest"),
        "draft_digest": draft["digest"],
        "selected_items": selected,
        "file_sha256": rendered.file_hashes,
        "management_operation_count": rendered.operation_count,
        "gaia_command_count": rendered.gaia_command_count,
        "expires_at": time.time() + APPROVAL_TTL,
        "approval_id": uuid.uuid4().hex,
    }


def validate_approval(plan, draft, approval):
    if (not _draft_is_current(draft)
            or not isinstance(approval, dict)
            or approval.get("envelope_type") != APPROVAL_TYPE
            or any(approval.get(key) != value for key, value in PAIR.items())
            or approval.get("source_digest") != draft.get("source_digest")
            or approval.get("target_digest") != draft.get("target_digest")
            or approval.get("draft_digest") != draft.get("digest")
            or type(approval.get("expires_at")) not in {int, float}
            or not math.isfinite(approval["expires_at"])
            or time.time() >= approval["expires_at"]):
        raise ValueError("A current signed Check Point design approval is required")
    selected = _selected(plan, approval.get("selected_items"))
    if selected != approval.get("selected_items"):
        raise ValueError("Check Point approval dependencies changed")
    rendered = CPManagementRenderer().render(plan, approved_items=selected)
    if (approval.get("file_sha256") != rendered.file_hashes
            or approval.get("management_operation_count") != rendered.operation_count
            or approval.get("gaia_command_count") != rendered.gaia_command_count):
        raise ValueError("Approved Check Point file bytes changed")
    return set(selected)
