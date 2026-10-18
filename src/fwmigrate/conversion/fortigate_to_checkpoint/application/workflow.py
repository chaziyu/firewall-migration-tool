"""Deterministic Check Point review, approval, and exact offline files."""

from dataclasses import replace
import hashlib
import json
import time
import uuid

from ..design.deterministic import (ARTIFACT_TYPE, PAIR, approve_draft, build_draft,
                                    validate_approval)
from ..models import CPFinding
from ..options import CPMigrationOptions
from ..planner import FortiGateToCheckPointPlanner
from ..rendering.management import (BINDINGS_FILE, GAIA_FILE, MANAGEMENT_FILE,
                                    CPManagementRenderer)
from ..review.workflow import build_review_report
from ..review.coverage import build_coverage
from ..target.evidence import build_target_evidence
from ..target.comparison import classify_target_reuse


_FILES = (MANAGEMENT_FILE, GAIA_FILE, BINDINGS_FILE)


def _options(value):
    if isinstance(value, CPMigrationOptions):
        return value
    if not isinstance(value, dict):
        raise ValueError("Check Point target mapping options must be an object")
    try:
        return CPMigrationOptions(**value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid Check Point target mapping options") from exc


def _plan(analysis, options, source_digest, *, target=None, target_source_text=None, target_metadata=None):
    parsed = _options(options)
    plan = FortiGateToCheckPointPlanner().plan(
        analysis.extracted.config, analysis.derived, parsed,
        source_inventory=analysis.extracted.source_objects,
    )
    if any(str(getattr(issue, "severity", "")).casefold() == "error"
           for issue in getattr(getattr(analysis, "validation", None), "issues", ())):
        plan = replace(plan, findings=(*plan.findings, CPFinding(
            "SOURCE_VALIDATION_ERRORS",
            "FortiGate source validation errors must be resolved before approval.",
            parsed.source_vdom, "source", "FortiGate")))
    evidence = None
    if target is not None:
        evidence = build_target_evidence(target, target_source_text, target_metadata, parsed)
        plan = classify_target_reuse(plan, evidence)
    elif target_source_text is not None or target_metadata is not None:
        raise ValueError("Check Point target source and metadata require parsed evidence")
    draft = build_draft(plan, parsed, source_digest, evidence["digest"] if evidence else None)
    return plan, parsed, draft


def run_migration_pipeline(analysis, options=None, *, source_digest="cli-source", target=None, target_source_text=None,
                           target_metadata=None):
    plan, parsed, _ = _plan(analysis, options or {}, source_digest, target=target,
                            target_source_text=target_source_text, target_metadata=target_metadata)
    rendered = CPManagementRenderer().render(plan)
    return plan, rendered, parsed


def build_review(analysis, options, source_digest, *, target=None, target_source_text=None, target_metadata=None):
    plan, parsed, draft = _plan(analysis, options, source_digest, target=target,
                                target_source_text=target_source_text, target_metadata=target_metadata)
    rendered = CPManagementRenderer().render(plan)
    return {
        "draft": draft,
        "plan": plan,
        "options": parsed,
        "requirements": [{
            "key": item.key, "source_vdom": item.source_vdom, "source_kind": item.source_kind,
            "source_name": item.source_name, "target_field": item.target_field,
            "label": item.label, "value": item.value, "choices": list(item.choices),
        } for item in plan.decisions],
        "report": {**build_review_report(plan), **rendered.report,
                   "coverage": build_coverage(plan, analysis.extracted.source_objects, analysis.derived),
                   "destination_snapshot_compared": target is not None, "target_digest": draft.get("target_digest")},
        "rendered": rendered,
    }


def approve_design(review, signed_draft, selected_items):
    if (not isinstance(signed_draft, dict)
            or signed_draft.get("digest") != review["draft"].get("digest")):
        raise ValueError("Check Point draft changed; prepare the current design again")
    return approve_draft(review["plan"], signed_draft, selected_items)


def build_artifact(analysis, options, source_digest, approval, *, target=None, target_source_text=None, target_metadata=None):
    review = build_review(analysis, options, source_digest, target=target,
                         target_source_text=target_source_text, target_metadata=target_metadata)
    approved = validate_approval(review["plan"], review["draft"], approval)
    rendered = CPManagementRenderer().render(review["plan"], approved_items=approved)
    if rendered.file_hashes != approval.get("file_sha256"):
        raise ValueError("Approved Check Point file bytes changed")
    report = {
        **rendered.report,
        "destination_snapshot_compared": target is not None,
        "target_digest": review["draft"].get("target_digest"),
        "coverage": build_coverage(review["plan"], analysis.extracted.source_objects,
                                   analysis.derived, approved_items=approved),
        "source_digest": source_digest,
        "approved_design_digest": approval["draft_digest"],
        "approved_items": sorted(approved),
        "design_approval": approval,
        "expires_at": approval["expires_at"],
    }
    contents = {
        MANAGEMENT_FILE: rendered.management_text,
        GAIA_FILE: rendered.gaia_text,
        BINDINGS_FILE: rendered.bindings_text,
    }
    files = {name: {
        "content": content,
        "byte_count": len(content.encode("utf-8")),
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    } for name, content in contents.items()}
    return {
        "envelope_type": ARTIFACT_TYPE,
        **PAIR,
        "artifact_id": uuid.uuid4().hex,
        "files": files,
        "file_sha256": {name: row["sha256"] for name, row in files.items()},
        "report": report,
        "design_approval": approval,
        "source_digest": source_digest,
        "target_digest": review["draft"].get("target_digest"),
        "options": review["options"].to_dict(),
        "expires_at": approval["expires_at"],
        "deployment_available": False,
    }


def verify_export_artifact(artifact):
    if (not isinstance(artifact, dict) or artifact.get("envelope_type") != ARTIFACT_TYPE
            or any(artifact.get(key) != value for key, value in PAIR.items())
            or artifact.get("deployment_available") is not False):
        raise ValueError("A signed FortiGate to Check Point offline artifact is required")
    expires_at = artifact.get("expires_at")
    approval = artifact.get("design_approval")
    if (type(expires_at) not in {int, float} or time.time() >= expires_at
            or not isinstance(approval, dict) or approval.get("expires_at") != expires_at
            or approval.get("target_digest") != artifact.get("target_digest")
            or approval.get("source_digest") != artifact.get("source_digest")):
        raise ValueError("Check Point export approval is missing or expired")
    files = artifact.get("files")
    if not isinstance(files, dict) or set(files) != set(_FILES):
        raise ValueError("Check Point artifact file list is invalid")
    actual_hashes = {}
    for name in _FILES:
        row = files[name]
        if not isinstance(row, dict) or not isinstance(row.get("content"), str):
            raise ValueError("Check Point artifact contains an invalid file")
        raw = row["content"].encode("utf-8")
        actual = hashlib.sha256(raw).hexdigest()
        if row.get("byte_count") != len(raw) or row.get("sha256") != actual:
            raise ValueError("Check Point artifact file integrity check failed")
        actual_hashes[name] = actual
    report = artifact.get("report")
    if (artifact.get("file_sha256") != actual_hashes
            or approval.get("file_sha256") != actual_hashes
            or not isinstance(report, dict)
            or report.get("file_sha256") != actual_hashes
            or report.get("source_digest") != artifact.get("source_digest")
            or report.get("target_digest") != artifact.get("target_digest")
            or report.get("approved_design_digest") != approval.get("draft_digest")):
        raise ValueError("Check Point artifact report or file bindings do not match")
    try:
        management = json.loads(files[MANAGEMENT_FILE]["content"])
        bindings = json.loads(files[BINDINGS_FILE]["content"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Check Point JSON artifact is invalid") from exc
    if (management.get("format") != "check_point_management_api_request_spec_v1"
            or bindings.get("format") != "fortigate_to_checkpoint_binding_manifest_v1"
            or management.get("api_version") != artifact.get("options", {}).get("management_api_version")
            or management.get("operation_count") != report.get("management_operation_count")
            or len(files[GAIA_FILE]["content"].splitlines()) != report.get("gaia_command_count")):
        raise ValueError("Check Point artifact request counts or context do not match")
    for line in files[GAIA_FILE]["content"].splitlines():
        if not line.strip().casefold().startswith(("set static-route ", "set ipv6 static-route ")):
            raise ValueError("Check Point Gaia artifact contains an unverified command")
        if any(word in line.casefold() for word in ("save config", "publish", "install-policy", "commit")):
            raise ValueError("Check Point Gaia artifact contains a prohibited operation")
    return artifact


def export_decisions(source_digest, options):
    parsed = _options(options)
    return {"format_version": 1, "envelope_type": "fortigate_to_checkpoint_mapping_v1",
            **PAIR, "source_digest": source_digest, "options": parsed.to_dict()}


def import_decisions(document, source_digest):
    if (not isinstance(document, dict) or document.get("format_version") != 1
            or document.get("envelope_type") != "fortigate_to_checkpoint_mapping_v1"
            or document.get("source_digest") != source_digest
            or any(document.get(key) != value for key, value in PAIR.items())):
        raise ValueError("Check Point mapping proposal belongs to a different pair or source")
    return _options(document.get("options", {})).to_dict()


def write_files(rendered, output):
    CPManagementRenderer().write_files(rendered, output)
