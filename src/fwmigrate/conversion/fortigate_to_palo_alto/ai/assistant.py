"""Explicitly invoked, advisory AI operations for pair-specific review."""

import logging
import uuid

from fwmigrate.ai.errors import AIInvalidResponseError
from .context import build_ai_review_context
from .models import PANAIAssistKind, proposal_from_output
from .prompts import (ANALYSIS_PROMPT, ANALYSIS_SCHEMA, EXPLANATION_PROMPT,
                      EXPLANATION_SCHEMA, FG_PAN_AI_PROMPT_VERSION)
from .validator import validate_analysis_output, validate_explanation_output

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
        return built, cached
    data = ai_provider.generate_structured(system_prompt=ANALYSIS_PROMPT, payload=built["context"],
        schema_name="fg_pan_review_analysis", schema=ANALYSIS_SCHEMA)
    results = validate_analysis_output(data.data, groups=built["context"]["groups"],
        allowed_values=built["allowed_values"], max_results=settings.max_questions)
    refs = built["decision_refs"]
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
    built = _build_context(state, "explain", settings)
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


def _build_context(state, operation, settings, cursor=0):
    state = {key: state[key] for key in (
        "source_digest", "target_digest", "target_device", "decisions", "review_workflow",
        "review_context", "decision_candidates", "auto_decisions", "target_findings",
    )}
    state["operation"] = operation
    state["prompt_version"] = FG_PAN_AI_PROMPT_VERSION
    return build_ai_review_context(max_bytes=settings.max_context_bytes, max_groups=settings.max_review_groups,
                                   cursor=cursor, **state)


def _log_operation(operation, result, built):
    _LOGGER.info("AI review operation=%s provider=%s model=%s request_id=%s context_digest=%s input_tokens=%s output_tokens=%s proposals=%s",
                 operation, result.provider, result.model, result.request_id, built["context_digest"],
                 result.input_tokens, result.output_tokens, "validated")
