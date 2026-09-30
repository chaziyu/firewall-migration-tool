"""Server-side dependency-wave construction of an advisory PAN-OS design."""

from __future__ import annotations

import time
import uuid

from .models import PANAIProposal
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


def _retain_current_proposals(session, design, state):
    if session is None:
        return design.proposals, {}
    previous = session.design
    if (previous.source_digest, previous.target_digest, previous.target_device) != (
        design.source_digest, design.target_digest, design.target_device
    ):
        return (), {item.decision_key: "CONTEXT_CHANGED" for item in previous.proposals}
    current = design
    previous_by_key = {item.decision_key: item for item in previous.proposals}
    invalidated = {}
    graph = state["design_session"].dependency_graph
    order = graph.topological_order()
    for key in order:
        proposal = previous_by_key.pop(key, None)
        if proposal is None:
            continue
        decision = next((item for item in design.authoritative_decisions.decisions
                         if item.key == key), None)
        if decision is None or design.authoritative_value(proposal.decision_key) is not None:
            invalidated[key] = "CONTEXT_CHANGED"
            continue
        if any(current.provisional_value(dependency) != value
               for dependency, value in proposal.dependency_values):
            invalidated[key] = "CONTEXT_CHANGED"
            continue
        working = state_with_proposed_design(state, current)
        try:
            ai_advisor.revalidate_stored_proposal(
                working, proposal.to_dict(), proposed_design=current
            )
        except (ai_advisor.AdvisorError, ValueError):
            invalidated[key] = "CONTEXT_CHANGED"
            continue
        current = current.with_state(proposals=(*current.proposals, proposal))
    invalidated.update({key: "CONTEXT_CHANGED" for key in previous_by_key})
    return current.proposals, invalidated


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
        "candidate_count": len(request_item.get("candidates", ())),
        "target_field": request_item.get("target_field"),
        "request_bytes": prepared.get("request_bytes", 0),
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


def _failure_audit_record(session_id, failure, decision_key, created_at):
    return {
        "audit_id": uuid.uuid4().hex,
        "event": "AI_REQUEST_FAILED",
        "design_session_id": session_id,
        "created_at": created_at,
        **failure,
        "decision_key": decision_key,
        "engineer_action": "UNRESOLVED",
        "final_value": None,
    }


def build_ai_proposed_design(state, existing_session=None) -> PANProposedDesignSession:
    """Run ready decisions in batches until no validated proposal unlocks more work."""
    identity = (state.get("source_digest"), state.get("target_digest"), state.get("target_device"))
    if not all(identity):
        raise ValueError("Upload PAN-OS target XML and select a target device before requesting AI advice")
    design = PANProposedDesign(*identity, state["decisions"])
    proposals, invalidated = _retain_current_proposals(existing_session, design, state)
    design = design.with_state(proposals=proposals)
    session_id = existing_session.session_id if existing_session else uuid.uuid4().hex
    created_at = existing_session.created_at if existing_session else time.time()
    audit = [dict(row) for row in existing_session.audit] if existing_session else []
    if existing_session:
        retained_keys = {item.decision_key for item in proposals}
        for old in existing_session.design.proposals:
            if old.decision_key in retained_keys:
                continue
            for row in audit:
                if row.get("decision_key") == old.decision_key and row.get("engineer_action") is None:
                    row["engineer_action"] = "UNRESOLVED"
                    row["failure_category"] = invalidated.get(old.decision_key, "CONTEXT_CHANGED")
    graph = state["design_session"].dependency_graph
    maximum_iterations = max(1, len(state["decisions"].decisions) + 1)
    iterations = 0
    failure_category = None
    failures = []
    failed_keys = set()
    stable = True

    def record_failure(error, prepared, keys, provider, model):
        nonlocal failure_category
        failure = ai_advisor.failure_record(error, prepared, provider=provider, model=model)
        if not failure.get("decision_keys"):
            failure["decision_keys"] = list(keys)
            failure["batch_size"] = len(keys)
        failed_keys.update(failure["decision_keys"])
        failure_category = failure_category or failure["failure_category"]
        failures.append(failure)
        affected = failure["decision_keys"] or list(keys)
        for key in affected:
            audit.append(_failure_audit_record(session_id, failure, key, time.time()))

    def record_repair(result, prepared, keys, provider, model):
        nonlocal failure_category
        for failure in result.failures:
            failure = dict(failure)
            failed_keys.update(failure.get("decision_keys") or keys)
            failure_category = failure_category or failure.get("failure_category", "AI_INTERNAL_ERROR")
            failures.append(failure)
            for key in failure.get("decision_keys") or keys:
                audit.append(_failure_audit_record(session_id, failure, key, time.time()))
        if result.exhausted:
            conflicts = [item["decision_key"] for item in result.proposals
                         if item.get("validation_status") == "CONFLICT"]
            if conflicts:
                failure = ai_advisor.failure_record(
                    ai_advisor.AdvisorRequestError(
                        "Conflicts remained after the configured repair passes.",
                        reason="REPAIR_EXHAUSTED",
                    ), prepared, provider=provider, model=model,
                )
                failure["failure_category"] = "AI_REPAIR_EXHAUSTED"
                failure["decision_keys"] = conflicts
                failure["batch_size"] = len(conflicts)
                failed_keys.update(conflicts)
                failure_category = failure_category or "AI_REPAIR_EXHAUSTED"
                failures.append(failure)
                for key in conflicts:
                    audit.append(_failure_audit_record(session_id, failure, key, time.time()))

    while iterations < maximum_iterations:
        working = state_with_proposed_design(state, design)
        ready = tuple(key for key in ai_advisor.ready_proposal_keys(working, design)
                      if key not in failed_keys)
        if not ready:
            break
        previous_keys = {item.decision_key for item in design.proposals}
        wave_proposals = []
        iterations += 1
        working = state_with_proposed_design(state, design)
        tiers = ai_advisor.classify_advisor_tiers(working, ready)
        pending_batches = []
        for tier in ("simple", "complex"):
            tier_keys = [key for key in ready if tiers.get(key, "complex") == tier]
            batch_size = ai_advisor._max_decisions() if tier == "simple" else 1
            pending_batches.extend(
                (tier_keys[offset:offset + batch_size], tier)
                for offset in range(0, len(tier_keys), batch_size)
            )
        while pending_batches:
            keys, tier = pending_batches.pop(0)
            working = state_with_proposed_design(state, design)
            provider = ai_advisor.advisor_provider()
            model = (ai_advisor.groq_model(tier) if provider == "groq"
                     else ai_advisor.advisor_model())
            prepared = None
            try:
                prepared = ai_advisor.build_proposal_context(
                    working,
                    list(keys),
                    model=model,
                    provider=provider,
                    proposed_design=design,
                )
            except ai_advisor.AdvisorRequestError as exc:
                if len(keys) > 1:
                    middle = len(keys) // 2
                    pending_batches[0:0] = [(keys[:middle], tier), (keys[middle:], tier)]
                    continue
                record_failure(exc, None, keys, provider, model)
                continue
            try:
                batch = ai_advisor.request_proposals(prepared)
            except ai_advisor.AdvisorError as exc:
                if len(keys) > 1 and exc.code in {
                    "AI_REQUEST_REJECTED", "AI_RESPONSE_INVALID", "AI_PROPOSAL_INVALID", "AI_TIMEOUT",
                }:
                    middle = len(keys) // 2
                    pending_batches[0:0] = [(keys[:middle], tier), (keys[middle:], tier)]
                    continue
                record_failure(exc, prepared, keys, provider, model)
                continue
            repaired = ai_advisor.repair_conflicted_proposals(
                    working, tuple(item["decision_key"] for item in batch), batch,
                    proposed_design=design,
                )
            record_repair(repaired, prepared, keys, provider, model)
            wave_proposals.extend((item, prepared) for item in repaired.proposals)
        if wave_proposals:
            # Validate the full design together so individually safe choices can
            # still conflict when they claim the same scoped PAN-OS resource.
            proposal_map = {item.decision_key: item.to_dict() for item in design.proposals}
            prepared_by_key = {}
            for proposal, prepared in wave_proposals:
                proposal_map[proposal["decision_key"]] = proposal
                prepared_by_key[proposal["decision_key"]] = prepared
            whole = ai_advisor.validate_proposal_set(working, list(proposal_map.values()))
            conflicts = tuple(item["decision_key"] for item in whole if item["validation_status"] == "CONFLICT")
            if conflicts:
                repair_base = design.with_state(proposals=tuple(
                    item for item in design.proposals if item.decision_key not in conflicts
                ))
                repair_state = state_with_proposed_design(state, repair_base)
                repaired = ai_advisor.repair_conflicted_proposals(
                    repair_state, tuple(conflicts), whole, proposed_design=repair_base,
                )
                record_repair(repaired, None, tuple(conflicts), "groq", ai_advisor.groq_model("repair"))
                whole = repaired.proposals
            design = design.with_state(proposals=tuple(PANAIProposal.from_dict(item) for item in whole))
            for item in design.proposals:
                if item.decision_key not in previous_keys:
                    prepared = prepared_by_key.get(item.decision_key)
                    if prepared:
                        audit.append(_audit_record(session_id, item, prepared, time.time()))
        if not wave_proposals or not ({item.decision_key for item in design.proposals} - previous_keys):
            break
    else:
        stable = False

    final_state = state_with_proposed_design(state, design)
    ready_unresolved = []
    for key in ai_advisor.ready_proposal_keys(final_state, design):
        provider = ai_advisor.advisor_provider()
        model = ai_advisor.model_for_decisions(final_state, [key], provider=provider)
        try:
            ai_advisor.build_proposal_context(
                final_state, [key], model=model, provider=provider, proposed_design=design
            )
        except ai_advisor.AdvisorRequestError:
            continue
        ready_unresolved.append(key)
    return PANProposedDesignSession(
        session_id=session_id,
        created_at=created_at,
        design=design,
        stable=stable,
        iterations=iterations,
        audit=tuple(audit),
        failure_category=failure_category,
        failures=tuple(failures),
        ai_eligible_decision_keys=tuple(ready_unresolved),
        dependency_graph=graph,
    )
