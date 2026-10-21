"""Deterministic Cisco FTD review, approval, and exact offline files."""

from dataclasses import replace
import hashlib
import json
import math
import time
import uuid

from ..design.deterministic import (
    ARTIFACT_TYPE,
    PAIR,
    approve_draft,
    build_draft,
    validate_approval,
)
from ..design.proposals import propose_new_target
from ..models import FTDFinding
from ..options import FTDMigrationOptions
from ..planner import PaloAltoToCiscoFTDPlanner
from ..planning.source_scope import source_scopes as _get_source_scopes
from ..rendering.fmc import (
    BINDINGS_FILE,
    CURL_FILE,
    INSTRUCTIONS_FILE,
    OPERATION_FILE,
    FMCRequestRenderer,
)
from ..review.coverage import build_coverage
from ..review.workflow import build_review_report
from ..target.comparison import classify_target_reuse
from ..target.evidence import build_target_evidence


_FILES = (OPERATION_FILE, BINDINGS_FILE, INSTRUCTIONS_FILE)


def source_scopes(analysis):
    return _get_source_scopes(analysis.config)


def _options(value):
    if isinstance(value, FTDMigrationOptions):
        return value
    if not isinstance(value, dict):
        raise ValueError("Cisco FTD target mapping options must be an object")
    try:
        return FTDMigrationOptions(**value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid Cisco FTD target mapping options") from exc


def _plan(analysis, options, source_digest, *, target=None, target_source_text=None, target_metadata=None):
    parsed = propose_new_target(analysis.config, _options(options))
    if parsed.target_mode == "new" and any(value is not None for value in (target, target_source_text, target_metadata)):
        raise ValueError("New-target creation cannot use existing-target comparison evidence")

    plan = PaloAltoToCiscoFTDPlanner().plan(
        analysis.config,
        analysis.derived,
        parsed,
        source_inventory=analysis.config.source_inventory,
    )

    if any(
        str(getattr(issue, "severity", "")).casefold() == "error"
        for issue in getattr(getattr(analysis, "validation", None), "issues", ())
    ):
        plan = replace(
            plan,
            items=tuple(replace(row, blockers=(*row.blockers, "SOURCE_VALIDATION_ERRORS")) for row in plan.items),
            findings=(
                *plan.findings,
                FTDFinding(
                    "SOURCE_VALIDATION_ERRORS",
                    "PAN-OS source validation errors must be resolved before approval.",
                    parsed.source_scope,
                    "source",
                    "PAN-OS",
                ),
            ),
        )

    evidence = None
    if target is not None:
        evidence = build_target_evidence(target, target_source_text, target_metadata, parsed)
        plan = classify_target_reuse(plan, evidence)
    elif target_source_text is not None or target_metadata is not None:
        raise ValueError("Cisco FTD target source and metadata require parsed evidence")
    elif parsed.target_mode == "existing":
        plan = replace(
            plan,
            items=tuple(
                replace(row, blockers=(*row.blockers, "EXISTING_TARGET_SNAPSHOT_REQUIRED"))
                for row in plan.items
            ),
        )

    draft = build_draft(plan, parsed, source_digest, evidence["digest"] if evidence else None)
    return plan, parsed, draft


def run_migration_pipeline(
    analysis,
    options=None,
    *,
    source_digest="cli-source",
    target=None,
    target_source_text=None,
    target_metadata=None,
):
    plan, parsed, _ = _plan(
        analysis,
        options or {},
        source_digest,
        target=target,
        target_source_text=target_source_text,
        target_metadata=target_metadata,
    )
    rendered = FMCRequestRenderer().render(plan)
    return plan, rendered, parsed


def build_review(
    analysis,
    options,
    source_digest,
    *,
    target=None,
    target_source_text=None,
    target_metadata=None,
):
    plan, parsed, draft = _plan(
        analysis,
        options,
        source_digest,
        target=target,
        target_source_text=target_source_text,
        target_metadata=target_metadata,
    )
    rendered = FMCRequestRenderer().render(plan)
    return {
        "draft": draft,
        "plan": plan,
        "options": parsed,
        "requirements": [
            {
                "key": item.key,
                "source_scope": item.source_scope,
                "source_kind": item.source_kind,
                "source_name": item.source_name,
                "target_field": item.target_field,
                "label": item.label,
                "value": item.value,
                "choices": list(item.choices),
            }
            for item in plan.decisions
        ],
        "report": {
            **build_review_report(plan),
            **rendered.report,
            "coverage": build_coverage(plan, analysis.config.source_inventory, analysis.derived),
            "destination_snapshot_compared": target is not None,
            "target_digest": draft.get("target_digest"),
        },
        "rendered": rendered,
    }


def approve_design(review, signed_draft, selected_items):
    if (
        not isinstance(signed_draft, dict)
        or signed_draft.get("digest") != review["draft"].get("digest")
    ):
        raise ValueError("Cisco FTD draft changed; prepare the current design again")
    return approve_draft(review["plan"], signed_draft, selected_items)


def build_artifact(
    analysis,
    options,
    source_digest,
    approval,
    *,
    target=None,
    target_source_text=None,
    target_metadata=None,
):
    review = build_review(
        analysis,
        options,
        source_digest,
        target=target,
        target_source_text=target_source_text,
        target_metadata=target_metadata,
    )
    approved = validate_approval(review["plan"], review["draft"], approval)
    rendered = FMCRequestRenderer().render(review["plan"], approved_items=approved)
    if rendered.file_hashes != approval.get("file_sha256"):
        raise ValueError("Approved Cisco FTD file bytes changed")

    report = {
        **rendered.report,
        "destination_snapshot_compared": target is not None,
        "target_digest": review["draft"].get("target_digest"),
        "coverage": build_coverage(
            review["plan"],
            analysis.config.source_inventory,
            analysis.derived,
            approved_items=approved,
        ),
        "source_digest": source_digest,
        "approved_design_digest": approval["draft_digest"],
        "approved_items": sorted(approved),
        "design_approval": approval,
        "expires_at": approval["expires_at"],
    }
    contents = {name: raw.decode("utf-8") for name, raw in rendered.files.items()}
    files = {
        name: {
            "content": content,
            "byte_count": len(content.encode("utf-8")),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
        for name, content in contents.items()
    }
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
    if (
        not isinstance(artifact, dict)
        or artifact.get("envelope_type") != ARTIFACT_TYPE
        or any(artifact.get(key) != value for key, value in PAIR.items())
        or artifact.get("deployment_available") is not False
    ):
        raise ValueError("A signed PAN-OS to Cisco FTD offline artifact is required")

    expires_at = artifact.get("expires_at")
    approval = artifact.get("design_approval")
    if (
        type(expires_at) not in {int, float}
        or not math.isfinite(expires_at)
        or time.time() >= expires_at
        or not isinstance(approval, dict)
        or approval.get("expires_at") != expires_at
        or approval.get("target_digest") != artifact.get("target_digest")
        or approval.get("source_digest") != artifact.get("source_digest")
    ):
        raise ValueError("Cisco FTD export approval is missing or expired")

    files = artifact.get("files")
    expected_files = (
        (*_FILES, CURL_FILE)
        if artifact.get("options", {}).get("target_mode") == "new"
        else _FILES
    )
    if not isinstance(files, dict) or set(files) != set(expected_files):
        raise ValueError("Cisco FTD artifact file list is invalid")

    actual_hashes = {}
    for name in expected_files:
        row = files[name]
        if not isinstance(row, dict) or not isinstance(row.get("content"), str):
            raise ValueError("Cisco FTD artifact contains an invalid file")
        raw = row["content"].encode("utf-8")
        actual = hashlib.sha256(raw).hexdigest()
        if row.get("byte_count") != len(raw) or row.get("sha256") != actual:
            raise ValueError("Cisco FTD artifact file integrity check failed")
        actual_hashes[name] = actual

    report = artifact.get("report")
    if (
        artifact.get("file_sha256") != actual_hashes
        or approval.get("file_sha256") != actual_hashes
        or not isinstance(report, dict)
        or report.get("file_sha256") != actual_hashes
        or report.get("source_digest") != artifact.get("source_digest")
        or report.get("target_digest") != artifact.get("target_digest")
        or report.get("approved_design_digest") != approval.get("draft_digest")
    ):
        raise ValueError("Cisco FTD artifact report or file bindings do not match")

    try:
        operations = json.loads(files[OPERATION_FILE]["content"])
        bindings = json.loads(files[BINDINGS_FILE]["content"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Cisco FTD JSON artifact is invalid") from exc

    if (
        operations.get("format") != "cisco_fmc_rest_api_request_spec_v1"
        or bindings.get("format") != "palo_alto_to_cisco_ftd_binding_manifest_v1"
        or operations.get("api_version") != artifact.get("options", {}).get("fmc_api_version")
        or operations.get("operation_count") != report.get("fmc_operation_count")
    ):
        raise ValueError("Cisco FTD artifact request counts or context do not match")

    return artifact


def export_decisions(source_digest, options):
    parsed = _options(options)
    return {
        "format_version": 1,
        "envelope_type": "palo_alto_to_cisco_ftd_mapping_v1",
        **PAIR,
        "source_digest": source_digest,
        "options": parsed.to_dict(),
    }


def import_decisions(document, source_digest):
    if (
        not isinstance(document, dict)
        or document.get("format_version") != 1
        or document.get("envelope_type") != "palo_alto_to_cisco_ftd_mapping_v1"
        or document.get("source_digest") != source_digest
        or any(document.get(key) != value for key, value in PAIR.items())
    ):
        raise ValueError("Cisco FTD mapping proposal belongs to a different pair or source")
    return _options(document.get("options", {})).to_dict()


def write_files(rendered, output):
    FMCRequestRenderer().write_files(rendered, output)
