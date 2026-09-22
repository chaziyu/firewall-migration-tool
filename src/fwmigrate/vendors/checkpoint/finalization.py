from __future__ import annotations

from fwmigrate.extraction.models import (
    DependencyRecord,
    ExtractionResult,
    ExtractionStatus,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_extraction_result
from fwmigrate.ir import IRConfig

from .coverage import aggregate_checkpoint_coverage, apply_checkpoint_coverage
from .fidelity import apply_checkpoint_fidelity
from .group_fidelity import apply_checkpoint_group_fidelity
from .models import CheckPointExportBundle


def finalize_checkpoint_extraction(
    canonical_ir: IRConfig,
    source_sections: list[SourceSectionResult],
    inventory_items: list[SourceInventoryItem],
    unsupported_items: list[UnsupportedItem],
    dependencies: list[DependencyRecord],
    bundle: CheckPointExportBundle,
) -> ExtractionResult:
    """Apply coverage, safety, sanitization, and fidelity after all extraction stages."""
    coverage = aggregate_checkpoint_coverage(
        inventory_items,
        bundle.responses,
        bundle.collection_completeness,
    )
    apply_checkpoint_coverage(source_sections, coverage)

    review_items = [
        item for item in inventory_items
        if item.requires_manual_review
        or item.status in {
            ExtractionStatus.PARTIALLY_NORMALIZED,
            ExtractionStatus.UNSUPPORTED,
            ExtractionStatus.PARSE_ERROR,
        }
    ]
    blocking_reasons = list(dict.fromkeys(
        reason
        for item in review_items
        for reason in (item.notes or [f"{item.source_path}:{item.name or '<unnamed>'}"])
    ))
    if unsupported_items and not blocking_reasons:
        blocking_reasons.append("checkpoint-unsupported-source-semantics")
    requires_manual_review = bool(review_items or unsupported_items)
    generation_safe = not blocking_reasons
    canonical_ir.generation_safe = generation_safe
    canonical_ir.generation_blocking_reasons = list(blocking_reasons)
    canonical_ir.requires_manual_review = requires_manual_review

    result = sanitize_extraction_result(ExtractionResult(
        canonical_ir=canonical_ir,
        source_sections=source_sections,
        coverage=coverage,
        inventory_items=inventory_items,
        unsupported_items=unsupported_items,
        dependencies=dependencies,
        requires_manual_review=requires_manual_review,
        migration_complete=not requires_manual_review,
        generation_safe=generation_safe,
        blocking_reasons=blocking_reasons,
    ))
    return apply_checkpoint_fidelity(apply_checkpoint_group_fidelity(result))


__all__ = ["finalize_checkpoint_extraction"]
