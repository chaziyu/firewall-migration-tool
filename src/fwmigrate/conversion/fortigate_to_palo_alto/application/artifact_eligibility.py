"""Approval binding for browser-held FortiGate -> PAN-OS artifacts.

Callers authenticate both envelopes before checking these pair-specific facts.
"""

from dataclasses import asdict
import math
import time

from ..design.draft import design_digest
from ..plan_dependencies import item_key

DESIGN_APPROVAL_TTL_SECONDS = 24 * 60 * 60


class ArtifactEligibilityError(ValueError):
    """Fixed public error explaining why engineer review must be renewed."""


def approval_is_current(approval):
    expires = approval.get("expires_at")
    return (type(expires) in {int, float} and math.isfinite(expires)
            and time.time() < expires)


def validate_artifact_approval(rendered, document, approval):
    report = rendered.report
    if approval.get("envelope_type") != "pan_design_approval":
        raise ArtifactEligibilityError("A signed design approval is required; prepare and approve the design again")
    if not approval_is_current(approval):
        raise ArtifactEligibilityError("Design approval has expired; prepare and approve the design again")
    context = approval["context"]
    if (report.get("approved_design_digest") != approval.get("draft_digest")
            or not approval.get("draft_digest")
            or report.get("source", {}).get("digest") != context.get("source_digest")
            or document.get("source_digest") != context.get("source_digest")):
        raise ArtifactEligibilityError("Artifact approval belongs to a different source or design")
    target = report.get("target_evidence") or {}
    if (target.get("config_digest") != context.get("reference_digest")
            or target.get("device") != context.get("target_device")
            or target.get("serial") != context.get("target_serial")):
        raise ArtifactEligibilityError("Artifact approval belongs to different target evidence")
    fields = ('value', 'review_state', 'approved_operation', 'approval_context',
              'evidence_source', 'evidence_type', 'evidence_value', 'target_object',
              'evidence_target_digest', 'evidence_target_device')
    for row in document.get("decisions", ()):
        if row.get("review_state") == "CONFIRMED" or row.get("mode") == "AUTO":
            if {field: row.get(field) for field in fields} != approval.get("decisions", {}).get(row['key']):
                raise ArtifactEligibilityError("Artifact decisions differ from the approved design")
    for item in report.get("items", ()):
        if item.get("render_disposition") == "BLOCK":
            continue
        row = approval.get("configuration", {}).get(item["item_key"])
        if (not row or row.get("status") != "READY"
                or row.get("operation") != item.get("render_disposition")
                or row.get("target_name") != item.get("target_name")
                or row.get("target_scope") != item.get("target_vsys")):
            raise ArtifactEligibilityError("Artifact contains unapproved configuration")


def validate_approved_plan(plan, approval):
    from ..target.target_plan_validation import _items

    current = {item_key(item): item for item in _items(plan)}
    for key, row in approval["configuration"].items():
        if key not in current or design_digest(row["configuration"]) != design_digest(asdict(current[key])):
            raise ArtifactEligibilityError("Approved configuration changed; prepare and approve the design again")


def deployment_serial(rendered, document, approval):
    validate_artifact_approval(rendered, document, approval)
    if rendered.report.get("plan_status") != "READY" or not rendered.commands:
        raise ArtifactEligibilityError("Candidate deployment requires a READY artifact with commands")
    context = approval["context"]
    serial = context.get("target_serial")
    if (context.get("reference_role") != "DESTINATION"
            or not rendered.report.get("destination_verified")
            or not isinstance(serial, str) or not serial.strip()):
        raise ArtifactEligibilityError("Approved destination serial evidence is required before candidate preparation")
    return serial
