"""Review, approve and build immutable offline Junos artifacts."""

from dataclasses import replace
import hashlib
import time
import uuid

from ..design.deterministic import PAIR, approve_draft, build_draft, export_decisions as export_mapping, import_decisions as import_mapping, validate_approval
from ..options import SRXMigrationOptions
from ..design.proposals import build_target_proposals
from ..planner import PaloAltoToJuniperSRXPlanner
from ..plan_dependencies import validate_plan
from ..rendering.renderer import JunosSetRenderer
from ..requirements import build_mapping_requirements
from ..review.coverage import build_coverage
from ..review.workflow import build_review_report
from ..target.evidence import build_target_evidence
from ..target.comparison import classify_target_reuse


ARTIFACT_TYPE = "palo_alto_to_juniper_srx_artifact_v2"


def _options(value):
    if isinstance(value, SRXMigrationOptions):
        return value
    if not isinstance(value, dict):
        raise ValueError("SRX target mapping options must be an object")
    try:
        return SRXMigrationOptions(**value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid PAN-OS to SRX target mapping options") from exc


def _plan(analysis, options, *, target=None, target_source_text=None, target_metadata=None):
    parsed = _options(options)
    if target is None:
        parsed, _ = build_target_proposals(analysis.config, analysis.derived, parsed)
    plan = PaloAltoToJuniperSRXPlanner().plan(analysis.config, analysis.derived, parsed)
    evidence = None
    if target is not None:
        evidence = build_target_evidence(target, target_source_text, target_metadata, parsed)
        plan = replace(plan, items=classify_target_reuse(plan, evidence))
    elif target_source_text is not None or target_metadata is not None:
        raise ValueError("Junos target configuration, parsed evidence and metadata must be provided together")
    errors = [issue for issue in getattr(analysis.validation, "issues", ())
              if str(getattr(issue, "severity", "")).lower() == "error"]
    if errors:
        plan = replace(plan, items=tuple(replace(row, blockers=tuple(dict.fromkeys((*row.blockers, "SOURCE_VALIDATION_ERRORS"))))
                                         for row in plan.items),
                       findings=(*plan.findings, "PAN-OS source validation errors block approval."))
    return validate_plan(plan), parsed, evidence


def build_review(analysis, options, source_digest, *, target=None, target_source_text=None, target_metadata=None):
    plan, parsed, evidence = _plan(analysis, options, target=target,
                                   target_source_text=target_source_text, target_metadata=target_metadata)
    rendered = JunosSetRenderer().render(plan)
    report = build_review_report(plan)
    report["coverage"] = build_coverage(plan, analysis.config.source_inventory)
    report.update({"source_digest": source_digest, "target_digest": None,
                   "command_count": rendered.command_count, "command_sha256": rendered.command_sha256,
                   "command_preview": rendered.command_text, "offline_export": True,
                   "verification": "Offline Junos set export; target compatibility, hardware, capacity and live device acceptance are unverified."})
    if evidence:
        required_families = {family for row in plan.items
                             for family in ({"address": ("addresses",), "address_group": ("addresses",),
                                            "service": ("applications",), "service_group": ("applications",),
                                            "interface": ("interfaces",), "zone": ("zones",),
                                            "static_route": ("static_routes",), "policy": ("policies", "nat"),
                                            "source_nat": ("nat",), "source_nat_pool": ("nat",)}.get(row.family, ()))}
        evidence_complete = (not evidence.global_blockers and all(
            family in evidence.complete_families and not evidence.blockers_for(family)
            for family in required_families))
        report.update({"destination_snapshot_compared": True, "target_digest": evidence.digest,
                       "snapshot_evidence_complete": evidence_complete,
                       "destination_comparison": {"context": evidence.context, "version": evidence.version,
                         "mode": evidence.mode, "complete_families": sorted(evidence.complete_families),
                         "global_blockers": list(evidence.global_blockers),
                         "family_blockers": {family: list(rows) for family, rows in evidence.family_blockers if rows}}})
    else:
        report["target_digest"] = None
    return {"draft": build_draft(plan, source_digest, parsed, evidence), "requirements": build_mapping_requirements(analysis.config, analysis.derived, parsed),
            "report": report, "plan": plan, "options": parsed, "target_evidence": evidence}


def approve_design(review, signed_draft, selected_items):
    if not isinstance(signed_draft, dict) or signed_draft.get("digest") != review["draft"]["digest"]:
        raise ValueError("Draft changed; prepare and review the current migration again")
    return approve_draft(review["plan"], review["draft"], selected_items, review.get("target_evidence"))


def build_artifact(analysis, options, source_digest, approval, *, target=None, target_source_text=None, target_metadata=None):
    review = build_review(analysis, options, source_digest, target=target,
                          target_source_text=target_source_text, target_metadata=target_metadata)
    selected, rendered = validate_approval(review["plan"], review["draft"], approval, review.get("target_evidence"))
    command_bytes = rendered.command_text.encode("utf-8")
    command_digest = hashlib.sha256(command_bytes).hexdigest()
    report = {**review["report"], **build_review_report(review["plan"], approved_items=selected),
              "source_digest": source_digest, "selected_items": selected, "selected_item_count": len(selected),
              "approved_design_digest": approval["draft_digest"], "command_count": rendered.command_count,
              "command_sha256": command_digest, "command_preview": rendered.command_text,
              "target_digest": review["draft"].get("target_digest"),
              "deployment_available": False, "offline_export": True}
    return {"envelope_type": ARTIFACT_TYPE, **PAIR, "artifact_id": str(uuid.uuid4()),
            "source_digest": source_digest, "target_digest": review["draft"].get("target_digest"), "options": review["options"].to_dict(),
            "command_text": rendered.command_text, "command_count": rendered.command_count,
            "command_sha256": command_digest, "report": report, "design_approval": approval,
            "expires_at": approval["expires_at"], "deployment_available": False}


def verify_export_artifact(artifact):
    if (not isinstance(artifact, dict) or artifact.get("envelope_type") != ARTIFACT_TYPE
            or any(artifact.get(key) != value for key, value in PAIR.items())
            or artifact.get("deployment_available") is not False):
        raise ValueError("A signed PAN-OS to Juniper SRX offline artifact is required")
    expires = artifact.get("expires_at")
    text = artifact.get("command_text")
    report = artifact.get("report")
    if type(expires) not in {int, float} or time.time() >= expires or not isinstance(text, str) or not isinstance(report, dict):
        raise ValueError("SRX export approval has expired or the artifact is invalid")
    count = text.count("\n") if text.endswith("\n") else (1 if text else 0)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if (artifact.get("command_count") != count or artifact.get("command_sha256") != digest
            or report.get("command_count") != count or report.get("command_sha256") != digest
            or report.get("source_digest") != artifact.get("source_digest")
            or report.get("target_digest") != artifact.get("target_digest")
            or artifact.get("design_approval", {}).get("target_digest") != artifact.get("target_digest")
            or artifact.get("design_approval", {}).get("expires_at") != expires):
        raise ValueError("SRX artifact command count, digest or source does not match")
    return artifact


def export_decisions(source_digest, options):
    return export_mapping(source_digest, options)


def import_decisions(document, source_digest):
    return import_mapping(document, source_digest)
