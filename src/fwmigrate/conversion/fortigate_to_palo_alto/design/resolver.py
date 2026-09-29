from __future__ import annotations

from .graph import build_decision_graph
from .session import create_design_session
from ..automation import run_automation_until_stable
from ..target_validation import validate_against_target


def resolve_design_session_until_stable(
    config,
    derived,
    decisions,
    target=None,
    device=None,
    *,
    target_evidence=None,
    enabled_policies=(),
    source_digest=None,
    requirements=None,
    max_iterations=None,
):
    """Resolve only deterministic results, then classify the complete design."""
    graph = build_decision_graph(config, derived, decisions, requirements)
    automation = run_automation_until_stable(
        config,
        derived,
        decisions,
        target,
        device,
        target_evidence=target_evidence,
        enabled_policies=enabled_policies,
        max_iterations=max_iterations,
    )
    findings = validate_against_target(config, automation.decisions, target, device)
    return create_design_session(
        automation.decisions,
        graph,
        source_digest=source_digest,
        target_evidence=target_evidence,
        deterministic_audit=automation.audit,
        findings=findings,
        iterations=automation.iterations,
        stable=automation.stable,
    )
