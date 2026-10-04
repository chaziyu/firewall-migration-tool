from __future__ import annotations

from .models import PANMigrationDesignSession
from ..decisions import PANDecisionMode, PANDecisionReviewState
from ..target.target_evidence import target_evidence_identity


def create_design_session(
    decisions,
    dependency_graph,
    *,
    source_digest=None,
    target_evidence=None,
    deterministic_audit=(),
    findings=(),
    iterations=0,
    stable=True,
):
    identity = target_evidence_identity(target_evidence) if target_evidence else None
    target_digest, target_device = identity if identity else (None, None)
    conflicted = {item.decision_key for item in findings}
    resolved, unresolved, unsupported = [], [], []
    for decision in decisions.decisions:
        if decision.key in conflicted:
            continue
        if decision.mode is PANDecisionMode.UNSUPPORTED:
            unsupported.append(decision.key)
        elif decision.mode is PANDecisionMode.AUTO or decision.review_state is PANDecisionReviewState.CONFIRMED:
            resolved.append(decision.key)
        else:
            unresolved.append(decision.key)
    return PANMigrationDesignSession(
        source_digest=source_digest,
        target_digest=target_digest,
        target_device=target_device,
        decisions=decisions,
        dependency_graph=dependency_graph,
        deterministic_audit=tuple(deterministic_audit),
        resolved=tuple(resolved),
        unresolved=tuple(unresolved),
        conflicted=tuple(sorted(conflicted)),
        unsupported=tuple(unsupported),
        iterations=iterations,
        stable=stable,
    )
