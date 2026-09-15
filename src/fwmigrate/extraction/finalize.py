from __future__ import annotations

from fwmigrate.extraction.models import ExtractionResult


def finalize_extraction(result: ExtractionResult) -> ExtractionResult:
    """Synchronize extraction and canonical-IR safety without changing accounting."""
    ir = result.canonical_ir
    reasons = list(dict.fromkeys([
        *result.blocking_reasons,
        *ir.generation_blocking_reasons,
    ]))
    safe = result.generation_safe and ir.generation_safe and not reasons
    review = result.requires_manual_review or ir.requires_manual_review

    result.blocking_reasons = reasons
    result.generation_safe = safe
    result.migration_complete = result.migration_complete and safe
    result.requires_manual_review = review
    ir.generation_blocking_reasons = list(reasons)
    ir.generation_safe = safe
    ir.requires_manual_review = review
    return result
