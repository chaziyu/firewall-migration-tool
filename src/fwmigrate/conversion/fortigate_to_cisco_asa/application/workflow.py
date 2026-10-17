"""Deterministic ASA review, approval, and exact offline artifact workflow."""

import uuid
from dataclasses import replace

from ..design.deterministic import (ARTIFACT_TYPE, PAIR, approve_draft, build_draft,
                                    digest, validate_approval)
from ..models import ASAFinding
from ..options import ASAMigrationOptions
from ..planner import FortiGateToCiscoASAPlanner
from ..rendering.renderer import ASACLIRenderer
from ..review.workflow import build_review_report
from ..target.comparison import _FAMILY_EVIDENCE, classify_target_reuse
from ..target.evidence import build_target_evidence


def _options(value):
    if isinstance(value, ASAMigrationOptions):
        return value
    if not isinstance(value, dict):
        raise ValueError("ASA target mapping options must be an object")
    try:
        return ASAMigrationOptions(**value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid ASA target mapping options") from exc


def _target_evidence(target, target_text, metadata):
    if target is None:
        if target_text is not None or metadata is not None:
            raise ValueError("ASA target text and metadata require a parsed target configuration")
        return None
    if not isinstance(target_text, str) or not metadata:
        raise ValueError("ASA destination comparison requires a target snapshot and completeness metadata")
    return build_target_evidence(target, digest({"text": target_text, "vendor": "cisco_asa"}), metadata)


def _prepare(analysis, options, source_digest, *, target=None, target_source_text=None,
             target_metadata=None):
    parsed = _options(options)
    evidence = _target_evidence(target, target_source_text, target_metadata)
    plan = FortiGateToCiscoASAPlanner().plan(
        analysis.extracted.config, analysis.derived, parsed,
        target_evidence=evidence, source_inventory=analysis.extracted.source_objects,
    )
    if any(str(getattr(issue, "severity", "")).casefold() == "error"
           for issue in getattr(getattr(analysis, "validation", None), "issues", ())):
        plan = replace(plan, findings=(*plan.findings, ASAFinding(
            "SOURCE_VALIDATION_ERRORS", "FortiGate source validation errors must be resolved before approval.",
            parsed.source_vdom, "source", "FortiGate")))
    if evidence is not None:
        plan = classify_target_reuse(plan, analysis.extracted.config, parsed, evidence)
    rendered = ASACLIRenderer().render(plan)
    required = set().union(*(_FAMILY_EVIDENCE[item.family] for item in plan.items
                             if item.family in _FAMILY_EVIDENCE))
    report = {**build_review_report(plan),
              "destination_snapshot_compared": evidence is not None,
              "snapshot_evidence_complete": bool(evidence and required <= set(evidence["complete_families"])),
              "destination_verified": False}
    draft = build_draft(plan, parsed, source_digest, evidence["digest"] if evidence else None)
    return {"plan": plan, "options": parsed, "rendered": rendered, "report": report,
            "draft": draft, "target_evidence": evidence}


def build_review(analysis, options, source_digest, *, target=None, target_source_text=None,
                 target_metadata=None):
    result = _prepare(analysis, options, source_digest, target=target,
                      target_source_text=target_source_text, target_metadata=target_metadata)
    return {"draft": result["draft"], "requirements": [
                {"key": row.key, "source_vdom": row.source_vdom, "source_kind": row.source_kind,
                 "source_name": row.source_name, "target_field": row.target_field, "label": row.label,
                 "value": row.value, "choices": list(row.choices)}
                for row in result["plan"].decisions],
            "report": result["report"], "plan": result["plan"], "options": result["options"]}


def approve_design(review, signed_draft, selected_items):
    if signed_draft.get("digest") != review["draft"].get("digest"):
        raise ValueError("ASA draft changed; prepare and review the current migration again")
    return approve_draft(review["plan"], signed_draft, selected_items)


def build_artifact(analysis, options, source_digest, approval, *, target=None,
                   target_source_text=None, target_metadata=None):
    review = _prepare(analysis, options, source_digest, target=target,
                      target_source_text=target_source_text, target_metadata=target_metadata)
    approved = validate_approval(review["plan"], review["draft"], approval)
    rendered = ASACLIRenderer().render(review["plan"], approved_items=approved)
    report = {**review["report"], "command_count": rendered.command_count,
              "command_sha256": rendered.command_sha256,
              "approved_design_digest": approval["draft_digest"],
              "approved_items": sorted(approved), "destination_verified": False,
              "verification": "Offline ASA configuration export; device acceptance and external routing or ARP behavior remain unverified."}
    return {"envelope_type": ARTIFACT_TYPE, **PAIR, "artifact_id": uuid.uuid4().hex,
            "commands": list(rendered.commands), "command_text": rendered.command_text,
            "command_count": rendered.command_count, "command_sha256": rendered.command_sha256,
            "report": report, "design_approval": approval,
            "source_digest": source_digest, "target_digest": review["draft"].get("target_digest"),
            "options": review["options"].to_dict(), "expires_at": approval["expires_at"]}


def verify_export_artifact(artifact):
    if (not isinstance(artifact, dict) or artifact.get("envelope_type") != ARTIFACT_TYPE
            or any(artifact.get(key) != value for key, value in PAIR.items())):
        raise ValueError("Invalid ASA export artifact")
    text = artifact.get("command_text")
    commands = artifact.get("commands")
    if (not isinstance(text, str) or not isinstance(commands, list)
            or text != ("\n".join(commands) + ("\n" if commands else ""))
            or digest(text) == "" or __import__("hashlib").sha256(text.encode()).hexdigest() != artifact.get("command_sha256")
            or artifact.get("command_count") != len(commands)
            or artifact.get("report", {}).get("command_sha256") != artifact.get("command_sha256")):
        raise ValueError("ASA export artifact integrity check failed")
    if any(line.strip().casefold().startswith(("write memory", "wr mem", "changeto ", "commit", "clear configure")) for line in commands):
        raise ValueError("ASA export artifact contains a device operation")
    return artifact


def export_decisions(source_digest, options):
    parsed = _options(options)
    return {"envelope_type": "fortigate_to_cisco_asa_mapping_v1", **PAIR,
            "source_digest": source_digest, "options": parsed.to_dict()}


def import_decisions(document, source_digest):
    if (not isinstance(document, dict) or document.get("envelope_type") != "fortigate_to_cisco_asa_mapping_v1"
            or any(document.get(key) != value for key, value in PAIR.items())
            or document.get("source_digest") != source_digest):
        raise ValueError("ASA mapping proposal belongs to a different pair or source")
    return _options(document.get("options", {})).to_dict()
