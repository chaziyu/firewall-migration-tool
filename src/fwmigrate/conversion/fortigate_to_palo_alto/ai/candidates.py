"""Deterministic candidate selection for AI migration advice."""

from __future__ import annotations

import hashlib
from collections import Counter

from .advisor_settings import _max_candidates_per_decision


def _candidate_id(decision_key, candidate) -> str:
    scope = candidate.get("target_scope")
    value = candidate.get("value")
    return hashlib.sha256(
        f"{decision_key}\0{scope or ''}\0{value}".encode("utf-8")
    ).hexdigest()


def _candidate_strength(candidate):
    strong_values = candidate.get("strong_evidence") or ()
    supporting_values = candidate.get("supporting_evidence") or ()
    strong = sum(isinstance(item, str) and bool(item) for item in strong_values[:6])
    supporting = sum(
        isinstance(item, str) and bool(item)
        for item in supporting_values[:6]
    )
    return (
        0 if candidate.get("class") == "STRONG" else 1,
        -strong,
        -supporting,
    )


def _select_ai_candidates(decision_key, raw_candidates, *, excluded_candidate_ids=()):
    """Return a bounded deterministic candidate subset without splitting evidence ties."""
    value_counts = Counter(
        item.get("value")
        for item in raw_candidates
        if item.get("class") in {"STRONG", "POSSIBLE"}
        and item.get("available", True)
        and not item.get("contested")
        and isinstance(item.get("value"), str)
    )
    excluded = set(excluded_candidate_ids)
    eligible = [
        item
        for item in raw_candidates
        if item.get("class") in {"STRONG", "POSSIBLE"}
        and item.get("available", True)
        and not item.get("contested")
        and isinstance(item.get("value"), str)
        and value_counts[item["value"]] == 1
        and _candidate_id(decision_key, item) not in excluded
    ]
    eligible.sort(key=lambda item: (
        _candidate_strength(item),
        item.get("target_scope") or "",
        item["value"],
    ))
    limit = _max_candidates_per_decision()
    if len(eligible) <= limit:
        return tuple(eligible), None
    if _candidate_strength(eligible[limit - 1]) == _candidate_strength(eligible[limit]):
        return (), "Candidate evidence is tied across the configured AI candidate cutoff."
    return tuple(eligible[:limit]), None
