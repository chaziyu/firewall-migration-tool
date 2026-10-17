"""Deterministic SRX review, approval and offline export lifecycle."""

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import time
import uuid

import yaml

from ..design.deterministic import (
    PAIR,
    approve_design as approve_plan,
    build_deterministic_draft,
    export_decisions as export_mapping,
    import_decisions as import_mapping,
    validate_approval,
)
from ..models import SRXFinding
from ..options import SRXMigrationOptions
from ..planner import FortiGateToJuniperSRXPlanner
from ..rendering.renderer import JunosSetRenderer
from ..requirements import build_mapping_requirements
from ..review.workflow import build_review_report
from ..target.comparison import compare_target_plan
from ..target.evidence import build_target_evidence


ARTIFACT_TYPE = "fortigate_to_juniper_srx_artifact_v1"


def _parsed_options(options):
    if isinstance(options, SRXMigrationOptions):
        return options
    if not isinstance(options, dict):
        raise ValueError("SRX target mapping options must be an object")
    try:
        return SRXMigrationOptions(**options)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid SRX target mapping options") from exc


def _plan(analysis, options, *, target=None, target_source_text=None, target_metadata=None):
    parsed = _parsed_options(options)
    plan = FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config,
        analysis.derived,
        parsed,
        source_inventory=analysis.extracted.source_objects,
    )
    validation_errors = any(
        str(getattr(issue, "severity", "")).lower() == "error"
        for issue in getattr(getattr(analysis, "validation", None), "issues", ())
    )
    if validation_errors:
        plan = replace(plan, findings=(*plan.findings, SRXFinding(
            "SOURCE_VALIDATION_ERRORS",
            "FortiGate source validation errors must be resolved before approval.",
            plan.source_vdom,
            "source",
            "FortiGate",
        )))
    evidence = None
    if target is not None:
        evidence = build_target_evidence(target, target_source_text, target_metadata, parsed)
        plan = compare_target_plan(plan, evidence)
    elif target_source_text is not None or target_metadata is not None:
        raise ValueError("Junos target source and parsed evidence must be provided together")
    return plan, parsed, evidence


def run_migration_pipeline(analysis, options=None, *, target=None, target_source_text=None, target_metadata=None):
    plan, parsed, _ = _plan(analysis, options or {}, target=target,
                            target_source_text=target_source_text, target_metadata=target_metadata)
    rendered = JunosSetRenderer().render(plan)
    return plan, rendered, parsed


def build_review(analysis, options, source_digest, *, target=None, target_source_text=None, target_metadata=None):
    plan, parsed, evidence = _plan(analysis, options, target=target,
                                  target_source_text=target_source_text, target_metadata=target_metadata)
    report = build_review_report(plan)
    if evidence:
        family_requirements = {
            "address": ("addresses",), "address_group": ("addresses",),
            "service": ("applications",), "service_group": ("applications",),
            "interface": ("interfaces",), "zone": ("zones",),
            "static_route": ("static_routes",), "schedule": ("schedules",),
            "policy": ("policies", "nat"), "source_nat": ("nat",),
        }
        required = {family for item in plan.items for family in family_requirements.get(item.family, ())}
        evidence_complete = not evidence.global_blockers and all(
            family in evidence.complete_families and not evidence.blockers_for(family) for family in required
        )
        report.update({
            "destination_verified": False,
            "destination_snapshot_compared": True,
            "snapshot_evidence_complete": evidence_complete,
            "target_digest": evidence.digest,
            "workflow_mode": "DESTINATION_AWARE",
            "destination_comparison": {
                "context": evidence.context,
                "version": evidence.version,
                "mode": evidence.mode,
                "complete_families": sorted(evidence.complete_families),
                "completeness_basis": "Operator-declared full configuration families; this is not live device validation.",
                "global_blockers": list(evidence.global_blockers),
                "family_blockers": {family: list(blockers) for family, blockers in evidence.family_blockers if blockers},
                "creation_operation": "Junos set export only; no deployment or commit is available.",
            },
        })
    draft = build_deterministic_draft(plan, source_digest, parsed, evidence)
    requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived, parsed)
    return {
        "draft": draft,
        "requirements": [asdict(requirement) for requirement in requirements],
        "report": report,
        "plan": plan,
        "options": parsed,
        "target_evidence": evidence,
    }


def approve_design(review, signed_draft, selected_items):
    draft = review["draft"]
    if (not isinstance(signed_draft, dict)
            or signed_draft.get("envelope_type") != draft["envelope_type"]
            or signed_draft.get("digest") != draft["digest"]
            or signed_draft.get("context_digest") != draft["context_digest"]):
        raise ValueError("Draft changed; prepare and review the current migration again")
    return approve_plan(review["plan"], draft, selected_items, review.get("target_evidence"))


def build_artifact(analysis, options, source_digest, approval, *, target=None, target_source_text=None, target_metadata=None):
    review = build_review(analysis, options, source_digest, target=target,
                          target_source_text=target_source_text, target_metadata=target_metadata)
    selected_items, rendered = validate_approval(review["plan"], review["draft"], approval)
    command_bytes = rendered.command_text.encode("utf-8")
    command_digest = hashlib.sha256(command_bytes).hexdigest()
    report = {
        **review["report"],
        "source_digest": source_digest,
        "target_digest": review["draft"].get("target_digest"),
        "selected_items": list(selected_items),
        "selected_item_count": len(selected_items),
        "approved_design_digest": approval["draft_digest"],
        "command_count": rendered.command_count,
        "command_sha256": command_digest,
        "offline_export": True,
        "deployment_available": False,
        "verification": (
            "Configuration snapshot comparison is bound to the reviewed artifact. Device acceptance, hardware compatibility, capacity, licensing and cabling remain unverified."
            if review["target_evidence"] else
            "Offline reviewed set export. Destination collisions, capacity, licensing, cabling and device acceptance are unverified."
        ),
    }
    return {
        "envelope_type": ARTIFACT_TYPE,
        **PAIR,
        "artifact_id": str(uuid.uuid4()),
        "source_digest": source_digest,
        "target_digest": review["draft"].get("target_digest"),
        "options": review["draft"]["options"],
        "command_text": rendered.command_text,
        "command_count": rendered.command_count,
        "command_sha256": command_digest,
        "report": report,
        "design_approval": approval,
        "expires_at": approval["expires_at"],
        "deployment_available": False,
    }


def verify_export_artifact(artifact):
    if (not isinstance(artifact, dict) or artifact.get("envelope_type") != ARTIFACT_TYPE
            or any(artifact.get(key) != value for key, value in PAIR.items())
            or artifact.get("deployment_available") is not False):
        raise ValueError("A signed FortiGate to Juniper SRX offline artifact is required")
    expires_at = artifact.get("expires_at")
    if type(expires_at) not in {int, float} or time.time() >= expires_at:
        raise ValueError("SRX export approval has expired")
    command_text = artifact.get("command_text")
    if not isinstance(command_text, str):
        raise ValueError("Invalid SRX command payload")
    command_count = command_text.count("\n") if command_text.endswith("\n") else (1 if command_text else 0)
    digest = hashlib.sha256(command_text.encode("utf-8")).hexdigest()
    report = artifact.get("report")
    approval = artifact.get("design_approval")
    if (not isinstance(report, dict) or report.get("source_digest") != artifact.get("source_digest")
            or not isinstance(approval, dict) or approval.get("expires_at") != expires_at
            or artifact.get("target_digest") != report.get("target_digest")
            or report.get("selected_items") != approval.get("selected_items")
            or artifact.get("command_count") != command_count
            or artifact.get("command_sha256") != digest
            or report.get("command_count") != command_count
            or report.get("command_sha256") != digest
            or report.get("approved_design_digest") != approval.get("draft_digest")):
        raise ValueError("SRX artifact payload or report integrity does not match")
    return artifact


def export_decisions(source_digest, options):
    return export_mapping(source_digest, options)


def import_decisions(document, source_digest):
    return import_mapping(document, source_digest)


def write_files(plan, rendered, output, source_digest, options, *, destination_report=None, target_digest=None):
    folder = Path(output)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "juniper_config.set").write_bytes(rendered.command_text.encode("utf-8"))
    report = {
        **build_review_report(plan),
        "source_digest": source_digest,
        "target_digest": target_digest,
        "destination_verified": bool(destination_report and destination_report.get("destination_verified")),
        "command_count": rendered.command_count,
        "command_sha256": rendered.command_sha256,
        "offline_export": True,
        "verification": "Offline set export; destination collisions, capacity, licensing, cabling and device acceptance are unverified.",
    }
    if destination_report:
        report.update({key: value for key, value in destination_report.items()
                       if key in {"destination_comparison", "destination_snapshot_compared",
                                  "snapshot_evidence_complete", "workflow_mode"}})
    (folder / "migration_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8",
    )
    decisions = export_decisions(source_digest, options)
    (folder / "migration_decisions.json").write_text(
        json.dumps(decisions, indent=2), encoding="utf-8",
    )
    (folder / "target_mapping.yaml").write_text(
        yaml.safe_dump(decisions["options"], sort_keys=False), encoding="utf-8",
    )
    return report
