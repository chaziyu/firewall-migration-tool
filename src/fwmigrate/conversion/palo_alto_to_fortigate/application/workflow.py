"""Deterministic orchestration; transport signing remains in web support."""
from dataclasses import asdict, replace
import hashlib
import uuid

from ..decisions import build_decision_set
from ..design.deterministic import PAIR, approve_draft, build_deterministic_draft, validate_approval
from ..options import FGMigrationOptions
from ..planner import PaloAltoToFortiGatePlanner
from ..requirements import build_mapping_requirements
from ..rendering.renderer import FGCLIRenderer
from ..review.workflow import build_review_issues
from ..target.comparison import classify_target_reuse
from ..target.evidence import build_target_evidence
from ..design.proposals import build_target_proposals
from ..planning.source_scope import identity, in_scope, select_source_scope


def run_migration_pipeline(analysis, options=None, *, target=None, target_digest=None, approved=None):
    try:
        parsed = options if isinstance(options, FGMigrationOptions) else FGMigrationOptions(**(options or {}))
    except TypeError as exc:
        raise ValueError("Invalid reverse-pair mapping document") from exc
    source, derived = analysis.config, analysis.derived
    plan = PaloAltoToFortiGatePlanner().plan(source, derived, parsed)
    if any(issue.severity == "error" for issue in analysis.validation.issues):
        plan = replace(plan, findings=(*plan.findings, "Source validation errors require correction before conversion."))
    evidence = build_target_evidence(target, target_digest) if target is not None else None
    plan = replace(plan, items=classify_target_reuse(plan.items, evidence, parsed))
    rendered = FGCLIRenderer().render(plan, parsed, approved=approved)
    return plan, rendered, parsed


def build_review(analysis, options, source_digest, *, target=None, target_digest=None):
    requested = options if isinstance(options, FGMigrationOptions) else FGMigrationOptions(**(options or {}))
    evidence = build_target_evidence(target, target_digest) if target is not None else None
    parsed, proposals = build_target_proposals(analysis.config, analysis.derived, requested, evidence)
    scope, _ = select_source_scope(analysis.config, parsed)
    rules = {identity(rule, "policy"): rule for rule in analysis.config.security_rules if scope and in_scope(rule, scope)}
    for key, fields in requested.policy_settings.items():
        if key not in rules:
            raise ValueError("Policy choices must select a current source policy in the selected scope")
        if any(getattr(rules[key], field) is not None for field in fields):
            raise ValueError("Target policy choices cannot override explicit source values")
    # These are provisional planner inputs. Executable artifacts still require signed approval of this exact design.
    plan, rendered, parsed = run_migration_pipeline(analysis, parsed, target=target, target_digest=target_digest)
    requirements = build_mapping_requirements(analysis.config, analysis.derived, parsed)
    by_key = {row["key"]: row for row in proposals}
    for row in requirements["decisions"]:
        if row["key"] in by_key:
            row.update(by_key[row["key"]])
        else:
            row.update({"mode": "REQUIRED" if row.get("value") in (None, "") else "SUGGESTED", "evidence_source": "ENGINEER"})
    effective = [{**asdict(row), "identity": list(row.identity)} for row in analysis.derived.effective_values
                 if row.identity[0] == parsed.source_scope]
    draft = build_deterministic_draft(plan, rendered, requirements, parsed, source_digest, target_digest,
                                      requested_options=requested.to_dict(), proposals=proposals, effective_values=effective)
    return {"draft": draft, "requirements": requirements, "decisions": build_decision_set(requirements),
            "resolved_options": parsed.to_dict(), "proposals": proposals, "effective_values": effective,
            "issues": build_review_issues(rendered.report), "report": rendered.report}


def approve_design(review, signed_draft, selected):
    draft = review["draft"]
    if signed_draft.get("envelope_type") != "fg_migration_draft_v1" or signed_draft.get("digest") != draft["digest"]:
        raise ValueError("Draft changed; prepare and review the current migration again")
    return approve_draft(draft, selected)


def build_artifact(analysis, options, source_digest, approval, *, target=None, target_digest=None):
    review = build_review(analysis, options, source_digest, target=target, target_digest=target_digest)
    approved = validate_approval(approval, review["draft"])
    _, rendered, _ = run_migration_pipeline(analysis, review["resolved_options"], target=target, target_digest=target_digest, approved=approved)
    report = {**rendered.report, "source_digest": source_digest, "target_digest": target_digest,
              "effective_values": review["effective_values"], "target_proposals": review["proposals"],
              "approved_design_digest": approval["draft_digest"], "workflow_mode": review["draft"]["context"]["workflow_mode"],
              "destination_verified": False, "verification":
              "Destination configuration comparison only; device compatibility, cabling, capacity and licensing remain unverified."
              if target is not None else
              "Offline reviewed FortiOS export. Destination collisions, device compatibility, cabling, capacity and licensing remain unverified."}
    return {"envelope_type": "fg_migration_artifact_v1", **PAIR, "artifact_id": str(uuid.uuid4()),
            "commands": list(rendered.commands), "command_count": len(rendered.commands), "command_sha256": report["command_sha256"],
            "report": report, "design_approval": approval, "expires_at": approval["expires_at"]}


def verify_export_artifact(artifact):
    import time

    if artifact.get("envelope_type") != "fg_migration_artifact_v1" or any(artifact.get(k) != v for k, v in PAIR.items()):
        raise ValueError("A signed PAN-OS to FortiGate export artifact is required")
    if type(artifact.get("expires_at")) not in {int, float} or not time.time() < artifact["expires_at"]:
        raise ValueError("Migration artifact approval has expired")
    commands = artifact.get("commands")
    if not isinstance(commands, list) or any(not isinstance(line, str) for line in commands):
        raise ValueError("Invalid artifact commands")
    actual = hashlib.sha256("\n".join(commands).encode()).hexdigest()
    if artifact.get("command_count") != len(commands) or artifact.get("command_sha256") != actual or artifact.get("report", {}).get("command_sha256") != actual:
        raise ValueError("Artifact command count or digest does not match")
    return artifact


def export_decisions(source_digest, options):
    parsed = FGMigrationOptions(**options)
    return {"format_version": 1, **PAIR, "source_digest": source_digest, "options": parsed.to_dict()}


def import_decisions(document, source_digest):
    if (not isinstance(document, dict) or document.get("format_version") != 1 or document.get("source_digest") != source_digest
            or any(document.get(k) != v for k, v in PAIR.items())):
        raise ValueError("Decision document belongs to a different pair, source or schema")
    # Import restores proposals only. Signed approval and execution authority are never imported.
    return export_decisions(source_digest, document.get("options", {}))["options"]


def write_files(rendered, output):
    FGCLIRenderer().write_files(rendered, output)
