from .. import (
    PANDecisionMode,
    PANDecisionReviewState,
    build_decision_set,
    build_recommendations,
)
from ..auto_decisions import classify_auto_decisions
from ..automation import AutomationPolicy
from ..design.resolver import resolve_design_session_until_stable
from ..requirements import build_mapping_requirements
from ..review_context import build_review_context
from ..review_evidence import build_review_evidence
from ..review_workflow import build_review_workflow
from ..target_evidence import reconcile_target_evidence, target_evidence_changed
from ..target_suggestions import discover_target_candidates, suggest_from_target
from ..target_validation import validate_against_target
from .decision_documents import load_decision_document


def decision_evidence(decision_set, target_findings):
    conflicts = {item.decision_key for item in target_findings}
    return {
        item.key: (
            "CONFLICT" if item.key in conflicts else
            item.evidence_source or (
                "ENGINEER" if item.review_state is PANDecisionReviewState.CONFIRMED else "SOURCE"
            )
        )
        for item in decision_set.decisions
    }


def auto_review_results(config, derived, decisions, target, device):
    results = classify_auto_decisions(config, derived, decisions, target, device)
    for finding in validate_against_target(config, decisions, target, device):
        result = results.setdefault(finding.decision_key, {})
        result.update(status="CONFLICT", reason=finding.message)
    return results


def evidence_summary(decision_set, evidence):
    values = [evidence[item.key] for item in decision_set.decisions]
    return {
        "target_backed": values.count("TARGET"),
        "source_only": values.count("SOURCE"),
        "conflicts": values.count("CONFLICT"),
        "required": sum(item.mode == PANDecisionMode.REQUIRED and item.review_state != PANDecisionReviewState.CONFIRMED
                         for item in decision_set.decisions),
        "confirmed": sum(item.review_state == PANDecisionReviewState.CONFIRMED for item in decision_set.decisions),
    }


def build_review_state(config, derived, source_digest, *, previous_document=None,
                       target=None, target_device=None, target_metadata=None,
                       target_device_count=0, apply_deterministic=False):
    requirements = build_mapping_requirements(config, derived)
    previous = load_decision_document(previous_document, source_digest) if previous_document is not None else None
    decisions = build_decision_set(config, derived, requirements, previous)
    decisions, invalidated_target_decisions = reconcile_target_evidence(decisions, target_metadata)
    review_evidence = build_review_evidence(config, derived)
    target_warnings = {}
    if target is not None and target_device:
        decisions, target_warnings = suggest_from_target(config, decisions, target, target_device)
    auto = auto_review_results(config, derived, decisions, target, target_device)
    design_session = resolve_design_session_until_stable(
        config,
        derived,
        decisions,
        target,
        target_device,
        source_digest=source_digest,
        target_evidence=target_metadata,
        requirements=requirements,
        enabled_policies=(
            (AutomationPolicy.AUTO_APPLY_VERIFIED, AutomationPolicy.AUTO_APPLY_DERIVED)
            if apply_deterministic else ()
        ),
    )
    decisions = design_session.decisions
    findings = validate_against_target(config, decisions, target, target_device)
    candidates = discover_target_candidates(config, decisions, target, target_device,
                                            evidence=review_evidence) if target is not None and target_device else {}
    evidence = decision_evidence(decisions, findings)
    context = build_review_context(config, decisions, candidates=candidates,
        target_available=target is not None, target_selected=bool(target_device),
        target_device_count=target_device_count, evidence=review_evidence)
    workflow = build_review_workflow(config, decisions, candidates=candidates,
        context=context, decision_evidence=evidence, target_warnings=target_warnings, target_findings=findings)
    recommendations = build_recommendations(config, derived, decisions, target, target_device)
    return {
        'requirements': requirements,
        'source_digest': source_digest,
        'target_digest': target_metadata.get('config_digest') if target_metadata else None,
        'target_device': target_device,
        'decisions': decisions,
        'design_session': design_session,
        'decision_candidates': candidates,
        'review_workflow': workflow,
        'review_context': context,
        'auto_decisions': auto,
        'target_findings': findings,
        'decision_evidence': evidence,
        'target_warnings': target_warnings,
        'recommendations': recommendations,
        'target_evidence_changed': target_evidence_changed(
            previous_document.get('target_evidence') if isinstance(previous_document, dict) else None,
            target_metadata,
        ) or bool(invalidated_target_decisions),
        'invalidated_target_decisions': invalidated_target_decisions,
    }
