"""Approval binding for browser-held FortiGate -> PAN-OS artifacts.

Callers authenticate both envelopes before checking these pair-specific facts.
"""

from dataclasses import asdict
import math
import re
import time

from fwmigrate.vendors.palo_alto.config_fingerprint import BASELINE_FORMAT

from ..design.draft import design_digest
from ..plan_dependencies import item_key

DESIGN_APPROVAL_TTL_SECONDS = 24 * 60 * 60


ARTIFACT_ELIGIBILITY_MESSAGES = {
    "APPROVAL_REQUIRED": "A signed design approval is required; prepare and approve the design again",
    "APPROVAL_EXPIRED": "Design approval has expired; prepare and approve the design again",
    "WORKFLOW_MISMATCH": "Artifact workflow differs from the approved design",
    "SOURCE_OR_DESIGN_MISMATCH": "Artifact approval belongs to a different source or design",
    "TARGET_EVIDENCE_MISMATCH": "Artifact approval belongs to different target evidence",
    "DECISIONS_MISMATCH": "Artifact decisions differ from the approved design",
    "CONFIGURATION_UNAPPROVED": "Artifact contains unapproved configuration",
    "CONFIGURATION_CHANGED": "Approved configuration changed; prepare and approve the design again",
    "OFFLINE_EXPORT": "Offline export cannot prepare a candidate; review destination evidence and approve a new design",
    "ARTIFACT_NOT_READY": "Candidate deployment requires a READY artifact with commands",
    "BASELINE_EVIDENCE_REQUIRED": "Approved destination baseline evidence is required; prepare and approve the design again",
    "SERIAL_EVIDENCE_REQUIRED": "Approved destination serial evidence is required before candidate preparation",
    "UPLOAD_REVIEW_EXPIRED": "Upload review has expired; review and approve the file again",
    "UPLOAD_DESTINATION_MISMATCH": "Upload approval belongs to a different destination host or port",
}


class ArtifactEligibilityError(ValueError):
    """Eligibility failure identified by a stable, non-public reason code."""

    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__()


def approval_is_current(approval):
    expires = approval.get("expires_at")
    return (type(expires) in {int, float} and math.isfinite(expires)
            and time.time() < expires)


def validate_artifact_approval(rendered, document, approval):
    report = rendered.report
    if approval.get("envelope_type") != "pan_design_approval":
        raise ArtifactEligibilityError("APPROVAL_REQUIRED")
    if not approval_is_current(approval):
        raise ArtifactEligibilityError("APPROVAL_EXPIRED")
    context = approval["context"]
    if report.get("workflow_mode", "DESTINATION_AWARE") != context.get("workflow_mode", "DESTINATION_AWARE"):
        raise ArtifactEligibilityError("WORKFLOW_MISMATCH")
    if (report.get("approved_design_digest") != approval.get("draft_digest")
            or not approval.get("draft_digest")
            or report.get("source", {}).get("digest") != context.get("source_digest")
            or document.get("source_digest") != context.get("source_digest")):
        raise ArtifactEligibilityError("SOURCE_OR_DESIGN_MISMATCH")
    target = report.get("target_evidence") or {}
    if (target.get("config_digest") != context.get("reference_digest")
            or target.get("device") != context.get("target_device")
            or target.get("serial") != context.get("target_serial")
            or target.get("baseline_sha256") != context.get("baseline_sha256")
            or target.get("baseline_format") != context.get("baseline_format")):
        raise ArtifactEligibilityError("TARGET_EVIDENCE_MISMATCH")
    fields = ('value', 'review_state', 'approved_operation', 'approval_context',
              'evidence_source', 'evidence_type', 'evidence_value', 'target_object',
              'evidence_target_digest', 'evidence_target_device')
    for row in document.get("decisions", ()):
        if row.get("review_state") == "CONFIRMED" or row.get("mode") == "AUTO":
            if {field: row.get(field) for field in fields} != approval.get("decisions", {}).get(row['key']):
                raise ArtifactEligibilityError("DECISIONS_MISMATCH")
    for item in report.get("items", ()):
        if item.get("render_disposition") == "BLOCK":
            continue
        row = approval.get("configuration", {}).get(item["item_key"])
        if (not row or row.get("status") != "READY"
                or row.get("operation") != item.get("render_disposition")
                or row.get("target_name") != item.get("target_name")
                or row.get("target_scope") != (item.get("virtual_router")
                    if item.get("source_object_type") == "static_route" else item.get("target_vsys"))):
            raise ArtifactEligibilityError("CONFIGURATION_UNAPPROVED")


def validate_approved_plan(plan, approval):
    from ..target.target_plan_validation import _items

    current = {item_key(item): item for item in _items(plan)}
    for key, row in approval["configuration"].items():
        if key not in current or design_digest(row["configuration"]) != design_digest(asdict(current[key])):
            raise ArtifactEligibilityError("CONFIGURATION_CHANGED")


def deployment_serial(rendered, document, approval):
    validate_artifact_approval(rendered, document, approval)
    if approval["context"].get("workflow_mode") == "OFFLINE_EXPORT":
        raise ArtifactEligibilityError("OFFLINE_EXPORT")
    if rendered.report.get("plan_status") != "READY" or not rendered.commands:
        raise ArtifactEligibilityError("ARTIFACT_NOT_READY")
    context = approval["context"]
    serial = context.get("target_serial")
    if (context.get("baseline_format") != BASELINE_FORMAT
            or not isinstance(context.get("baseline_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", context["baseline_sha256"])):
        raise ArtifactEligibilityError("BASELINE_EVIDENCE_REQUIRED")
    if (context.get("reference_role") != "DESTINATION"
            or not rendered.report.get("destination_verified")
            or not isinstance(serial, str) or not serial.strip()):
        raise ArtifactEligibilityError("SERIAL_EVIDENCE_REQUIRED")
    return serial
