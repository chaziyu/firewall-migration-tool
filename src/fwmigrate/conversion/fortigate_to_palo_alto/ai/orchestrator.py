"""Server-side dependency-wave construction of an advisory PAN-OS design."""

from __future__ import annotations

from dataclasses import replace
import time
import uuid

from .models import PANAIProposal, PANAIProposalAction
from .. import ai_advisor
from ..design.proposed import PANProposedDesign, PANProposedDesignSession
from ..review_evidence import build_review_evidence
from ..target_suggestions import discover_target_candidates


def state_with_proposed_design(state, design):
    result = dict(state, proposed_design=design)
    analysis = state.get("analysis")
    source = getattr(getattr(analysis, "extracted", None), "config", None)
    target_context = state.get("target_context")
    target = getattr(target_context, "analysis", None)
    if source is not None and target is not None and state.get("target_device"):
        result["decision_candidates"] = discover_target_candidates(
            source,
            state["decisions"],
            target,
            state["target_device"],
            evidence=build_review_evidence(source, analysis.derived),
            proposed_design=design,
        )
    return result


def _retain_current_proposals(session, design):
    if session is None:
        return design.proposals
    previous = session.design
    if (previous.source_digest, previous.target_digest, previous.target_device) != (
        design.source_digest, design.target_digest, design.target_device
    ):
        return ()
    current = design.with_state(proposals=previous.proposals)
    kept = []
    for proposal in previous.proposals:
        decision = next((item for item in design.authoritative_decisions.decisions
                         if item.key == proposal.decision_key), None)
        if decision is None or design.authoritative_value(proposal.decision_key) is not None:
            continue
        if any(current.provisional_value(key) != value for key, value in proposal.dependency_values):
            continue
        kept.append(proposal)
    return tuple(kept)


def _audit_record(session_id, proposal, prepared, created_at):
    request_item = next((item for item in prepared["request"]["decisions"]
                         if item["decision_id"] == prepared["by_decision"][proposal.decision_key]["decision_id"]), {})
    return {
        "audit_id": uuid.uuid4().hex,
        "design_session_id": session_id,
        "created_at": created_at,
        "decision_key": proposal.decision_key,
        "context_digest": proposal.context_digest,
        "dependency_values": [list(item) for item in proposal.dependency_values],
        "candidate_ids": [item["candidate_id"] for item in request_item.get("candidates", ())],
        "provider": proposal.provider,
        "model": proposal.model,
        "escalated_from": proposal.escalated_from,
        "failure_category": proposal.escalation_failure_category,
        "repair_pass": proposal.repair_pass,
        "proposal": {
            "action": proposal.action.value,
            "candidate_id": proposal.candidate_id,
            "proposed_value": proposal.proposed_value,
            "target_scope": proposal.target_scope,
            "evidence_refs": list(proposal.evidence_refs),
        },
        "validation_result": {
            "status": proposal.validation_status,
            "findings": list(proposal.validation_findings),
        },
        "engineer_action": None,
        "final_value": None,
    }


def build_ai_proposed_design(state, existing_session=None) -> PANProposedDesignSession:
    """Run ready decisions in batches until no validated proposal unlocks more work."""
    identity = (state.get("source_digest"), state.get("target_digest"), state.get("target_device"))
    if not all(identity):
        raise ValueError("Upload PAN-OS target XML and select a target device before requesting AI advice")
    design = PANProposedDesign(*identity, state["decisions"])
    proposals = _retain_current_proposals(existing_session, design)
    design = design.with_state(proposals=proposals)
    session_id = existing_session.session_id if existing_session else uuid.uuid4().hex
    created_at = existing_session.created_at if existing_session else time.time()
    audit = [dict(row) for row in existing_session.audit] if existing_session else []
    if existing_session:
        retained_keys = {item.decision_key for item in proposals}
        for old in existing_session.design.proposals:
            if old.decision_key in retained_keys:
                continue
            if any(design.provisional_value(key) != value for key, value in old.dependency_values):
                for row in audit:
                    if row.get("decision_key") == old.decision_key and row.get("engineer_action") is None:
                        row["engineer_action"] = "UNRESOLVED"
                        row["failure_category"] = "DEPENDENCY_CHANGED"
    graph = state["design_session"].dependency_graph
    maximum_iterations = max(1, len(state["decisions"].decisions) + 1)
    iterations = 0
    failure_category = None
    stable = True

    while iterations < maximum_iterations:
        working = state_with_proposed_design(state, design)
        ready = tuple(ai_advisor.ready_proposal_keys(working, design))
        if not ready:
            break
        previous_keys = {item.decision_key for item in design.proposals}
        wave_proposals = []
        iterations += 1
        for offset in range(0, len(ready), ai_advisor._max_decisions()):
            keys = ready[offset:offset + ai_advisor._max_decisions()]
            working = state_with_proposed_design(state, design)
            try:
                prepared = ai_advisor.build_proposal_context(
                    working,
                    list(keys),
                    model=ai_advisor.advisor_model(),
                    provider=ai_advisor.advisor_provider(),
                    proposed_design=design,
                )
                batch = ai_advisor.request_proposals(prepared)
                batch = ai_advisor.repair_conflicted_proposals(
                    working, tuple(item["decision_key"] for item in batch), batch,
                    proposed_design=design,
                )
                wave_proposals.extend((item, prepared) for item in batch)
            except Exception as exc:
                failure_category = exc.code if isinstance(exc, ai_advisor.AdvisorError) else "AI_INTERNAL_ERROR"
                stable = False
                break
        if wave_proposals:
            # Validate the full design together so individually safe choices can
            # still conflict when they claim the same scoped PAN-OS resource.
            proposal_map = {item.decision_key: item.to_dict() for item in design.proposals}
            prepared_by_key = {}
            for proposal, prepared in wave_proposals:
                proposal_map[proposal["decision_key"]] = proposal
                prepared_by_key[proposal["decision_key"]] = prepared
            whole = ai_advisor.validate_proposal_set(working, list(proposal_map.values()))
            conflicts = {item["decision_key"] for item in whole if item["validation_status"] == "CONFLICT"}
            if conflicts:
                repair_base = design.with_state(proposals=tuple(
                    item for item in design.proposals if item.decision_key not in conflicts
                ))
                repair_state = state_with_proposed_design(state, repair_base)
                whole = ai_advisor.repair_conflicted_proposals(
                    repair_state, tuple(conflicts), whole, proposed_design=repair_base,
                )
            design = design.with_state(proposals=tuple(PANAIProposal.from_dict(item) for item in whole))
            for item in design.proposals:
                if item.decision_key not in previous_keys:
                    prepared = prepared_by_key.get(item.decision_key)
                    if prepared:
                        audit.append(_audit_record(session_id, item, prepared, time.time()))
        if failure_category:
            break
        if not wave_proposals or not ({item.decision_key for item in design.proposals} - previous_keys):
            break
    else:
        stable = False

    return PANProposedDesignSession(
        session_id=session_id,
        created_at=created_at,
        design=design,
        stable=stable,
        iterations=iterations,
        audit=tuple(audit),
        failure_category=failure_category,
    )
