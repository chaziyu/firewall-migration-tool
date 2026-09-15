"""Source-context to target-scope validation for migration orchestration."""

from __future__ import annotations

from typing import Any


_FORTIGATE_MULTI_VDOM_BLOCKER = (
    "Multiple FortiGate VDOMs are present; target generation requires an explicit "
    "context-to-target-scope mapping"
)


def _source_contexts(extraction: Any) -> set[str]:
    contexts = {
        item.source_context or "root"
        for item in getattr(extraction, "inventory_items", [])
        if item.source_context
    }
    ir = getattr(extraction, "canonical_ir", None)
    if ir is None:
        return contexts
    for field_name in getattr(ir.__class__, "model_fields", {}):
        value = getattr(ir, field_name, None)
        if not isinstance(value, list):
            continue
        for item in value:
            if hasattr(item, "source_context"):
                context = getattr(item, "source_context", None)
                if context:
                    contexts.add(context)
    return contexts


def _reset_safety(extraction: Any) -> None:
    blockers = list(dict.fromkeys(getattr(extraction, "blocking_reasons", []) or []))
    extraction.blocking_reasons = blockers
    extraction.generation_safe = not blockers
    extraction.migration_complete = not blockers
    extraction.requires_manual_review = bool(blockers) or any(
        item.requires_manual_review
        for item in getattr(extraction, "inventory_items", [])
    )
    ir = extraction.canonical_ir
    ir.generation_blocking_reasons = list(blockers)
    ir.generation_safe = not blockers
    ir.requires_manual_review = extraction.requires_manual_review


def apply_context_mapping(request: Any, extraction: Any) -> list[str]:
    """Validate and apply orchestration-only source-context mapping.

    Source ``source_context`` values are never rewritten.  A valid mapping only
    removes the FortiGate extractor's generic multi-VDOM portability blocker;
    the target generator receives the mapping separately.
    """
    if request.source_vendor != "fortigate":
        return []

    contexts = _source_contexts(extraction)
    if len(contexts) <= 1:
        return []

    mapping = dict(getattr(request, "context_mapping", {}) or {})
    blockers = [
        reason
        for reason in extraction.blocking_reasons
        if reason != _FORTIGATE_MULTI_VDOM_BLOCKER
    ]

    missing = sorted(context for context in contexts if not mapping.get(context))
    extra = sorted(context for context in mapping if context not in contexts)
    target_scopes = [mapping[context] for context in contexts if mapping.get(context)]

    mapping_reasons: list[str] = []
    if missing:
        mapping_reasons.append(
            "Missing target scope mapping for FortiGate VDOM(s): " + ", ".join(missing)
        )
    if extra:
        mapping_reasons.append(
            "Context mapping contains unknown FortiGate VDOM(s): " + ", ".join(extra)
        )
    if len(target_scopes) != len(set(target_scopes)):
        mapping_reasons.append(
            "FortiGate multi-VDOM context mapping must use a distinct target scope for each source VDOM"
        )
    if request.target_vendor != "fortigate":
        mapping_reasons.append(
            f"Target '{request.target_vendor}' does not implement explicit FortiGate VDOM scope mapping"
        )
    if request.target_vendor == "fortigate" and request.target_format.lower() != "cli":
        mapping_reasons.append(
            "FortiGate multi-VDOM scope mapping is currently supported only for CLI generation"
        )

    if mapping_reasons:
        extraction.blocking_reasons = list(dict.fromkeys([*blockers, *mapping_reasons]))
        _reset_safety(extraction)
        return mapping_reasons

    extraction.blocking_reasons = blockers
    _reset_safety(extraction)
    return []


__all__ = ["apply_context_mapping"]
