"""Shared effective-value provenance and candidate history helpers."""

from __future__ import annotations

from typing import Any, MutableMapping

from fwmigrate.parsers.juniper_srx.extraction import sanitize_tokens

from fwmigrate.parsers.juniper_srx.model import (
    JuniperConfigContext,
    JuniperEffectiveCandidate,
    JuniperEffectiveProvenance,
    JuniperProvenanceKind,
    JuniperResolutionStatus,
)


def build_provenance(cmd, context=None) -> JuniperEffectiveProvenance:
    context = context or getattr(cmd, "context", None)
    return JuniperEffectiveProvenance(
        provenance_kind=(JuniperProvenanceKind.INHERITED_GROUP
                         if cmd.source_group else JuniperProvenanceKind.LOCAL),
        source_context=context,
        source_group_name=cmd.source_group,
        source_group_chain=tuple(cmd.source_group_chain),
        source_path=tuple(sanitize_tokens(cmd.source_group_path or tuple(cmd.tokens[1:]))),
        target_context=context,
        target_path=tuple(sanitize_tokens(cmd.target_path or tuple(cmd.tokens[1:]))),
        hierarchy_depth=cmd.hierarchy_depth,
        group_priority=cmd.group_priority,
        group_list_priority=cmd.group_list_priority,
        group_application_depth=cmd.group_application_depth,
        recursion_depth=cmd.group_recursion_depth,
        group_recursion_depth=cmd.group_recursion_depth,
        source_order=cmd.source_order or cmd.line_number,
    )


def _candidate(value: Any, field: str, cmd, *, status=JuniperResolutionStatus.EFFECTIVE,
               effective=True, reason=None, context=None) -> JuniperEffectiveCandidate:
    provenance = build_provenance(cmd, context)
    return JuniperEffectiveCandidate(
        value=value, field_key=field,
        target_path=tuple(sanitize_tokens(cmd.target_path or tuple(cmd.tokens[1:]))),
        provenance=provenance, status=status,
        effective=effective, shadowed=status is JuniperResolutionStatus.SHADOWED,
        excluded=status is JuniperResolutionStatus.EXCLUDED,
        inactive=status is JuniperResolutionStatus.INACTIVE, reason=reason,
        group_list_priority=provenance.group_list_priority,
        group_application_depth=provenance.group_application_depth,
        group_recursion_depth=provenance.group_recursion_depth,
        hierarchy_depth=provenance.hierarchy_depth,
        source_order=provenance.source_order,
    )


def build_candidate(value: Any, field: str, cmd, *, status=JuniperResolutionStatus.EFFECTIVE,
                    effective=True, reason=None, context=None) -> JuniperEffectiveCandidate:
    return _candidate(value, field, cmd, status=status, effective=effective,
                      reason=reason, context=context)


def _append(history: MutableMapping[str, list], field: str, candidate) -> None:
    entries = history.setdefault(field, [])
    identity = (candidate.field_key, candidate.value,
                candidate.target_path, candidate.provenance.source_group_chain if candidate.provenance else ())
    if any((item.field_key, item.value, item.target_path,
            item.provenance.source_group_chain if item.provenance else ()) == identity
           and item.status == candidate.status for item in entries):
        return
    entries.append(candidate)


def record_scalar_candidate(provenance: MutableMapping[str, JuniperEffectiveProvenance],
                            history: MutableMapping[str, list], field: str, value: Any,
                            cmd, context=None) -> JuniperEffectiveCandidate:
    for previous in effective_candidates(history, field):
        mark_candidate_shadowed(previous)
    candidate = _candidate(value, field, cmd, context=context)
    _append(history, field, candidate)
    provenance[field] = candidate.provenance
    return candidate


def record_list_candidate(history: MutableMapping[str, list], field: str, value: Any,
                          cmd, context=None) -> JuniperEffectiveCandidate:
    candidate = _candidate(value, field, cmd, context=context)
    _append(history, field, candidate)
    return candidate


def record_object_candidate(provenance, history, field, value, cmd, context=None):
    return record_scalar_candidate(provenance, history, field, value, cmd, context)


def record_member_candidate(history: MutableMapping[str, list], field: str, value: Any,
                            cmd, context=None) -> JuniperEffectiveCandidate:
    key = _semantic_key(value)
    for previous in effective_candidates(history, field):
        if _semantic_key(previous.value) == key:
            mark_candidate_shadowed(previous)
    candidate = _candidate(value, field, cmd, context=context)
    _append(history, field, candidate)
    return candidate


def _semantic_key(value: Any) -> str:
    if isinstance(value, dict):
        return repr(sorted(value.items()))
    return str(value).casefold()


def mark_existing_candidate_shadowed(candidate: JuniperEffectiveCandidate, reason=None) -> None:
    mark_candidate_shadowed(candidate, reason)


def mark_candidate_shadowed(candidate: JuniperEffectiveCandidate, reason=None) -> None:
    candidate.status = JuniperResolutionStatus.SHADOWED
    candidate.effective = False
    candidate.shadowed = True
    candidate.reason = reason


def record_excluded_candidate(history, field, value, cmd, reason="apply-groups-except", context=None):
    candidate = _candidate(value, field, cmd, status=JuniperResolutionStatus.EXCLUDED,
                          effective=False, reason=reason, context=context)
    _append(history, field, candidate)
    return candidate


def record_inactive_candidate(history, field, value, cmd, reason="inactive", context=None):
    candidate = _candidate(value, field, cmd, status=JuniperResolutionStatus.INACTIVE,
                          effective=False, reason=reason, context=context)
    _append(history, field, candidate)
    return candidate


def effective_candidates(history, field=None):
    values = history.get(field, []) if field is not None else [c for v in history.values() for c in v]
    return [c for c in values if c.status is JuniperResolutionStatus.EFFECTIVE and c.effective]


def is_effective_candidate(candidate) -> bool:
    return candidate is None or (candidate.status is JuniperResolutionStatus.EFFECTIVE and candidate.effective)


candidate_is_effective = is_effective_candidate
