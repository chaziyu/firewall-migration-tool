"""Explicitly invoked, advisory AI operations for pair-specific review."""

import logging
import uuid
from dataclasses import replace

from fwmigrate.ai.errors import AIInvalidResponseError
from .context import build_ai_review_context
from .models import PANAIAssistKind, PANAIReviewDraft, proposal_from_output
from .prompts import (ANALYSIS_PROMPT, ANALYSIS_SCHEMA, EXPLANATION_PROMPT,
                      EXPLANATION_SCHEMA, FG_PAN_AI_PROMPT_VERSION, SELECTION_PROMPT, SELECTION_SCHEMA,
                      COMPACT_SELECTION_PROMPT, COMPACT_SELECTION_SCHEMA)
from .validator import validate_analysis_output, validate_explanation_output, validate_selection_output

_LOGGER = logging.getLogger(__name__)


def _cache_key(provider, model, operation, digest, prompt_version):
    return (provider, model, operation, digest, prompt_version)


def analyze_review_groups(*, ai_provider, settings, state, cache, cursor=0):
    built = _build_context(state, "analysis", settings, cursor=cursor)
    if not built["context"]["groups"]:
        return built, ()
    key = _cache_key(settings.provider, settings.model, "analysis", built["context_digest"], FG_PAN_AI_PROMPT_VERSION)
    cached = cache.get_many(key)
    if cached:
        covered = {decision for proposal in cached for decision in proposal.decision_keys}
        built["covered_decision_keys"] = tuple(covered)
        built["omitted_decision_keys"] = tuple(decision for decision in built["decision_refs"].values()
                                               if decision not in covered)
        return built, cached
    data = ai_provider.generate_structured(system_prompt=ANALYSIS_PROMPT, payload=built["context"],
        schema_name="fg_pan_review_analysis", schema=ANALYSIS_SCHEMA)
    results = validate_analysis_output(data.data, groups=built["context"]["groups"],
        allowed_values=built["allowed_values"], max_results=settings.max_questions)
    refs = built["decision_refs"]
    covered = {item for result in results for item in result["decision_keys"]}
    built["covered_decision_keys"] = tuple(refs[key] for key in covered)
    built["omitted_decision_keys"] = tuple(refs[key] for key in refs if key not in covered)
    proposals = []
    for result in results:
        safe_keys = list(result["decision_keys"])
        affected = max((next(group["affected_count"] for group in built["context"]["groups"]
                             if key in {decision["key"] for decision in group["decisions"]})
                        for key in safe_keys), default=0)
        result["decision_keys"] = [refs[key] for key in safe_keys]
        for choice in result["choices"]:
            for assignment in choice["assignments"]:
                assignment["decision_key"] = refs[assignment["decision_key"]]
        proposal = proposal_from_output(output=result, kind=PANAIAssistKind(result["kind"]),
            proposal_id=uuid.uuid4().hex, context_digest=built["context_digest"], provider=data.provider,
            model=data.model, prompt_version=FG_PAN_AI_PROMPT_VERSION, affected_count=affected,
            state_digest=built["state_digest"], comparisons=result["comparisons"])
        proposals.append(proposal)
    cache.put_many(key, proposals)
    _log_operation("analysis", data, built)
    return built, tuple(proposals)


def explain_review_group(*, ai_provider, settings, state, group_identity, cache):
    built = _build_context(state, "explain", settings, group_identity=group_identity)
    group = next((item for item in built["context"]["groups"] if
                  (item["source_vdom"], item["source_kind"], item["source_name"]) == group_identity), None)
    if group is None:
        raise AIInvalidResponseError("The selected review group is not available for explanation")
    candidate_count = sum(len(item["candidates"]) for item in group["decisions"])
    if not candidate_count:
        raise AIInvalidResponseError("The selected review group has no target candidates to compare")
    group_context = {"group": group}
    from .sanitizer import sanitize_ai_context
    group_context = sanitize_ai_context(group_context, max_bytes=settings.max_context_bytes)
    import hashlib, json
    digest = hashlib.sha256(json.dumps({"state": built["context_digest"], "group": group_context,
        "operation": "explain", "prompt_version": FG_PAN_AI_PROMPT_VERSION}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    key = _cache_key(settings.provider, settings.model, "explain", digest, FG_PAN_AI_PROMPT_VERSION)
    cached = cache.get_many(key)
    if cached:
        return built, cached[0]
    result = ai_provider.generate_structured(system_prompt=EXPLANATION_PROMPT, payload=group_context,
        schema_name="fg_pan_candidate_comparison", schema=EXPLANATION_SCHEMA)
    output = validate_explanation_output(result.data, group=group)
    proposal = proposal_from_output(output=output, kind=PANAIAssistKind.CANDIDATE_COMPARISON,
        proposal_id=uuid.uuid4().hex, context_digest=digest, provider=result.provider, model=result.model,
        prompt_version=FG_PAN_AI_PROMPT_VERSION, affected_count=group["affected_count"],
        state_digest=built["state_digest"],
        comparisons=output["comparisons"])
    from dataclasses import replace
    proposal = replace(proposal, decision_keys=tuple(built["decision_refs"][item["key"]]
                                                       for item in group["decisions"]))
    cache.put_many(key, (proposal,))
    _log_operation("explain", result, built)
    return built, proposal


def suggest_review_selection(*, ai_provider, settings, state, group_identity, cache):
    built = _build_context(state, "select", settings, group_identity=group_identity)
    group = next((item for item in built["context"]["groups"] if
                  (item["source_vdom"], item["source_kind"], item["source_name"]) == group_identity), None)
    if group is None or not any(item["allowed_values"] for item in group["decisions"]):
        raise AIInvalidResponseError("The selected review group has no closed target options")
    if any(item["unexamined_options"] for item in group["decisions"]):
        raise AIInvalidResponseError("More than eight target options need engineer review")
    import hashlib, json
    group_context = {"group": group}
    digest = hashlib.sha256(json.dumps({"state": built["context_digest"], "group": group_context,
        "operation": "select", "prompt_version": FG_PAN_AI_PROMPT_VERSION}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    key = _cache_key(settings.provider, settings.model, "select", digest, FG_PAN_AI_PROMPT_VERSION)
    cached = cache.get_many(key) if cache is not None else ()
    if cached:
        return built, cached[0]
    if settings.provider == "local":
        compact, options = _compact_selection(group)
        data = ai_provider.generate_structured(system_prompt=COMPACT_SELECTION_PROMPT, payload=compact,
            schema_name="fg_pan_review_selection_compact", schema=COMPACT_SELECTION_SCHEMA)
        output = _expand_compact_selection(data.data, group, options)
    else:
        data = ai_provider.generate_structured(system_prompt=SELECTION_PROMPT, payload=group_context,
            schema_name="fg_pan_review_selection", schema=SELECTION_SCHEMA)
        output = data.data
    output = validate_selection_output(output, group=group, allowed_values=built["allowed_values"])
    refs = built["decision_refs"]
    assignments = [{"decision_key": refs[item["decision_key"]], "value": item["value"]}
                   for item in output["suggested_assignments"]]
    proposal_output = {"title": "AI selection suggestion",
        "summary": "An AI suggestion is ready for your review." if assignments else
                   "The available choices cannot be distinguished from current evidence.",
        "decision_keys": [refs[item] for item in output["decision_keys"]],
        "choices": ([{"label": "Use suggestion", "assignments": assignments}] if assignments else []),
        "suggested_value": assignments[0]["value"] if len(assignments) == 1 else None,
        "evidence": output["evidence"], "rationale": output["rationale"],
        "missing_information": output["missing_information"],
        "limitations": [*output["alternatives"], *output["limitations"]]}
    proposal = proposal_from_output(output=proposal_output, kind=PANAIAssistKind.SELECTION_SUGGESTION,
        proposal_id=uuid.uuid4().hex, context_digest=digest, provider=data.provider, model=data.model,
        prompt_version=FG_PAN_AI_PROMPT_VERSION, affected_count=group["affected_count"],
        state_digest=built["state_digest"])
    if cache is not None:
        cache.put_many(key, (proposal,))
    _log_operation("select", data, built)
    return built, proposal


def _compact_selection(group):
    compact = {"operation": "select", "group": {field: group[field] for field in
        ("source_vdom", "source_kind", "source_name", "confirmed_engineer_context")}, "decisions": []}
    options = {}
    for index, decision in enumerate(group["decisions"], 1):
        decision_id = f"d{index}"
        row = {"id": decision_id, "target_field": decision["target_field"],
               "source": decision["source"], "options": []}
        for number, option in enumerate(decision["candidates"], 1):
            option_id = f"o{index}_{number}"
            facts = list(dict.fromkeys((*option["strong_evidence"], *option["supporting_evidence"])))
            evidence = {f"e{number}": fact for number, fact in enumerate(facts, 1)}
            row["options"].append({"id": option_id, "value": option["value"],
                "evidence": [{"id": fact_id, "text": fact} for fact_id, fact in evidence.items()]})
            options[option_id] = (decision["key"], option["value"], evidence)
        compact["decisions"].append(row)
    return compact, options


def _expand_compact_selection(output, group, options):
    if (not isinstance(output, dict) or not isinstance(output.get("choices"), list)
            or len(output["choices"]) > 8
            or not isinstance(output.get("missing_information"), list)
            or not isinstance(output.get("limitations"), list)):
        raise AIInvalidResponseError("AI response has invalid compact choices")
    assignments, evidence, seen = [], [], set()
    decision_ids = {item["key"]: f"d{index}" for index, item in enumerate(group["decisions"], 1)}
    signatures = {}
    for key, value, facts in options.values():
        signatures.setdefault(key, []).append(frozenset(facts.values()))
    indistinguishable = {key for key, values in signatures.items()
                         if len(values) > 1 and len(set(values)) == 1}
    choices = {}
    for choice in output["choices"]:
        if not isinstance(choice, dict) or choice.get("option_id") not in options:
            raise AIInvalidResponseError("AI choice references an unknown option")
        key, value, facts = options[choice["option_id"]]
        if choice.get("decision_id") != decision_ids[key]:
            raise AIInvalidResponseError("AI choice references an unknown decision")
        ids = choice.get("evidence_ids")
        if not isinstance(ids, list) or not ids or len(ids) > 8 or any(item not in facts for item in ids):
            raise AIInvalidResponseError("AI choice references unsupported evidence")
        choices.setdefault(key, []).append((value, [facts[item] for item in ids]))
    for key, entries in choices.items():
        if len(entries) != 1 or key in indistinguishable:
            continue
        value, facts = entries[0]
        seen.add(key)
        assignments.append({"decision_key": key, "value": value})
        evidence.extend(facts)
    alternatives = [value for key, value, _ in options.values() if key not in seen]
    return {"decision_keys": [item["key"] for item in group["decisions"]],
        "suggested_assignments": assignments, "evidence": list(dict.fromkeys(evidence)),
        "rationale": [], "alternatives": list(dict.fromkeys(alternatives)),
        "missing_information": [*output["missing_information"],
            *("AI returned competing options for this decision" for entries in choices.values()
              if len(entries) != 1),
            *("Available options have indistinguishable evidence" for key in choices
              if key in indistinguishable)],
        "limitations": output.get("limitations")}


def prepare_review_draft(*, ai_provider, settings, state, cache, draft=None):
    """Prepare one review group per call; keep every unresolved key visible."""
    built = _build_context(state, "select", settings)
    groups = [group for group in state["review_workflow"].get("review_groups", ())
              if group.get("queue") != "COMPLETE"]
    source_types = {(item.vdom or "root", item.name):
                    "vlan" if item.vlanid is not None else (item.type or "").casefold()
                    for item in state["analysis"].extracted.config.interfaces}
    source_parents = {(item.vdom or "root", item.name): item.interface
                      for item in state["analysis"].extracted.config.interfaces if item.interface}
    zone_members = {(item.vdom or "root", item.name): set(item.members or ())
                    for item in state["analysis"].extracted.config.zones}
    groups.sort(key=lambda group: (0 if group["source_kind"] == "vdom" else
        4 if group["source_kind"] == "zone" else
        3 if source_types.get((group["source_vdom"], group["source_name"])) in {"tunnel", "ipsec", "gre"} else
        2 if source_types.get((group["source_vdom"], group["source_name"])) == "vlan" else 1,
        group["source_vdom"], group["source_name"]))
    if draft is None:
        draft = PANAIReviewDraft(uuid.uuid4().hex, built["state_digest"], 0, 0, len(groups))
    if draft.state_digest != built["state_digest"] or draft.total_groups != len(groups):
        raise AIInvalidResponseError("AI draft is stale; prepare it again")
    if draft.cursor == draft.total_groups:
        cache.put_many((settings.provider, settings.model, "draft", draft.proposal_id), (draft,))
        return draft
    group = groups[draft.cursor]
    identity = (group["source_vdom"], group["source_kind"], group["source_name"])
    by_key = {item.key: item for item in state["decisions"].decisions}
    pending = [key for key in group.get("decision_keys", ()) if key in by_key
               and by_key[key].review_state.value == "PENDING"
               and by_key[key].mode.value not in {"AUTO", "UNSUPPORTED"}]
    proposed = {assignment.decision_key: assignment.value for proposal in draft.proposals
                for choice in proposal.choices for assignment in choice.assignments}
    tentative = state.copy()
    tentative["decisions"] = replace(state["decisions"], decisions=tuple(
        replace(item, value=proposed[item.key]) if item.key in proposed else item
        for item in state["decisions"].decisions))
    target_context = state.get("target_context")
    if target_context and target_context.selected_device:
        from ..ai_selection_options import build_ai_selection_options
        from ..review_evidence import build_review_evidence
        analysis = state["analysis"]
        tentative["ai_selection_options"] = build_ai_selection_options(
            analysis.extracted.config, analysis.derived, tentative["decisions"],
            target_context.analysis, target_context.selected_device,
            build_review_evidence(analysis.extracted.config, analysis.derived))
    proposals = draft.proposals
    blockers = list(draft.blockers)
    dependencies = list(draft.dependencies)
    try:
        selected = _build_context(tentative, "select", settings, group_identity=identity)
        rows = selected["context"]["groups"][0]["decisions"] if selected["context"]["groups"] else []
        if any(item["unexamined_options"] for item in rows):
            raise AIInvalidResponseError("More than eight target options need engineer review")
        if rows:
            try:
                _, proposal = suggest_review_selection(ai_provider=ai_provider, settings=settings,
                    state=tentative, group_identity=identity, cache=None)
            except AIInvalidResponseError:
                _, proposal = suggest_review_selection(ai_provider=ai_provider, settings=settings,
                    state=tentative, group_identity=identity, cache=None)
            chosen = {item.decision_key for choice in proposal.choices for item in choice.assignments}
            if chosen != set(pending) and pending:
                _, retry = suggest_review_selection(ai_provider=ai_provider, settings=settings,
                    state=tentative, group_identity=identity, cache=None)
                retry_keys = {item.decision_key for choice in retry.choices for item in choice.assignments}
                if len(retry_keys) > len(chosen):
                    proposal, chosen = retry, retry_keys
            if chosen:
                proposals += (proposal,)
                current = {item.decision_key: item.value for choice in proposal.choices
                           for item in choice.assignments}
                for key in chosen:
                    item = by_key[key]
                    required = [earlier for earlier in (proposed | current) if earlier != key
                                and by_key[earlier].source_vdom == item.source_vdom
                                and ((item.target_field != "vsys" and by_key[earlier].target_field == "vsys")
                                     or (item.target_field == "target_zone" and
                                         by_key[earlier].source_name == item.source_name and
                                         by_key[earlier].target_field == "target_interface")
                                     or (item.target_field == "target_interface" and
                                         by_key[earlier].source_name == source_parents.get(
                                             (item.source_vdom, item.source_name)) and
                                         by_key[earlier].target_field == "target_interface")
                                     or (item.source_kind == "zone" and
                                         by_key[earlier].source_name in zone_members.get(
                                             (item.source_vdom, item.source_name), ()) and
                                         by_key[earlier].target_field == "target_interface"))]
                    if required:
                        dependencies.append({"decision_key": key, "depends_on": required})
            for key in pending:
                if key not in chosen:
                    blockers.append({"decision_key": key, "reason":
                        "; ".join(proposal.missing_information) or "AI could not support a selection",
                        "alternatives": list(proposal.limitations)})
        else:
            blockers.extend({"decision_key": key, "reason": "No closed target options; target evidence or design input is required"}
                            for key in pending)
    except AIInvalidResponseError as exc:
        blockers.extend({"decision_key": key, "reason": str(exc)} for key in pending)
    updated = replace(draft, revision=draft.revision + 1, cursor=draft.cursor + 1,
                      proposals=proposals, blockers=tuple(blockers), dependencies=tuple(dependencies))
    cache.put_many((settings.provider, settings.model, "draft", draft.proposal_id), (updated,))
    return updated


def _build_context(state, operation, settings, cursor=0, group_identity=None):
    selection_options = state.get("ai_selection_options", {})
    state = {key: state[key] for key in (
        "source_digest", "target_digest", "target_device", "decisions", "review_workflow",
        "review_context", "decision_candidates", "auto_decisions", "target_findings",
    )}
    state["ai_selection_options"] = selection_options
    state["operation"] = operation
    state["prompt_version"] = FG_PAN_AI_PROMPT_VERSION
    return build_ai_review_context(max_bytes=settings.max_context_bytes, max_groups=settings.max_review_groups,
        group_identity=group_identity,
                                   cursor=cursor, **state)


def _log_operation(operation, result, built):
    _LOGGER.info("AI review operation=%s provider=%s model=%s request_id=%s context_digest=%s input_tokens=%s output_tokens=%s proposals=%s",
                 operation, result.provider, result.model, result.request_id, built["context_digest"],
                 result.input_tokens, result.output_tokens, "validated")
