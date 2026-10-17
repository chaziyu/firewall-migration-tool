"""Source, pair, options, target, dependency, and command-bound ASA approval."""

import hashlib
import json
import time
import uuid

from ..rendering.renderer import ASACLIRenderer
from ..validation import dispositions


PAIR = {"source_vendor": "fortigate", "target_vendor": "cisco_asa"}
DRAFT_TYPE = "fortigate_to_cisco_asa_draft_v1"
APPROVAL_TYPE = "fortigate_to_cisco_asa_approval_v1"
ARTIFACT_TYPE = "fortigate_to_cisco_asa_artifact_v1"
APPROVAL_TTL = 24 * 60 * 60


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_draft(plan, options, source_digest, target_digest=None):
    content = {"pair": PAIR, "source_digest": source_digest, "target_digest": target_digest,
               "options": options.to_dict(), "plan": {"items": [item.__dict__ if hasattr(item, "__dict__") else {
                   field: getattr(item, field) for field in item.__dataclass_fields__}
                   for item in plan.items], "findings": [
                       {field: getattr(row, field) for field in row.__dataclass_fields__} for row in plan.findings]}}
    content["digest"] = digest(content)
    content["envelope_type"] = DRAFT_TYPE
    return content


def _selected(plan, selected_items):
    by_key = {item.key: item for item in plan.items}
    if not isinstance(selected_items, list) or not selected_items or len(selected_items) != len(set(selected_items)):
        raise ValueError("Select at least one current ASA plan item")
    pending, chosen = list(selected_items), set()
    state = dispositions(plan)
    while pending:
        key = pending.pop()
        item = by_key.get(key)
        if item is None or state[key] == "BLOCK":
            raise ValueError("ASA approval contains an unknown or blocked item")
        if key in chosen:
            continue
        chosen.add(key)
        pending.extend(item.dependencies)
    return sorted(chosen)


def approve_draft(plan, draft, selected_items):
    if draft.get("envelope_type") != DRAFT_TYPE or draft.get("digest") != digest(
            {k: v for k, v in draft.items() if k not in {"digest", "envelope_type", "signature"}}):
        raise ValueError("ASA draft changed; prepare the current design again")
    if any(row.blocking for row in plan.findings):
        raise ValueError("Blocking source or target findings must be resolved before approval")
    selected = _selected(plan, selected_items)
    rendered = ASACLIRenderer().render(plan, approved_items=selected)
    return {"envelope_type": APPROVAL_TYPE, **PAIR, "source_digest": draft["source_digest"],
            "target_digest": draft.get("target_digest"), "draft_digest": draft["digest"],
            "selected_items": selected, "command_count": rendered.command_count,
            "command_sha256": rendered.command_sha256, "expires_at": time.time() + APPROVAL_TTL,
            "approval_id": uuid.uuid4().hex}


def validate_approval(plan, draft, approval):
    if (not isinstance(approval, dict) or approval.get("envelope_type") != APPROVAL_TYPE
            or any(approval.get(key) != value for key, value in PAIR.items())
            or approval.get("draft_digest") != draft.get("digest")
            or approval.get("source_digest") != draft.get("source_digest")
            or approval.get("target_digest") != draft.get("target_digest")
            or type(approval.get("expires_at")) not in {int, float}
            or time.time() >= approval["expires_at"]):
        raise ValueError("A current signed ASA design approval is required")
    selected = _selected(plan, approval.get("selected_items"))
    if selected != approval.get("selected_items"):
        raise ValueError("ASA approval dependencies changed")
    rendered = ASACLIRenderer().render(plan, approved_items=selected)
    if rendered.command_count != approval.get("command_count") or rendered.command_sha256 != approval.get("command_sha256"):
        raise ValueError("Approved ASA command bytes changed")
    return set(selected)
