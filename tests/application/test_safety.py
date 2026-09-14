from types import SimpleNamespace

from fwmigrate.application.safety import (
    MigrationSafetyEvaluator,
    evaluate_generation_safety,
)
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig, IRMetadata


def _ir(**kwargs):
    return IRConfig(metadata=IRMetadata(source_vendor="source"), **kwargs)


def test_unsafe_extraction_blocks_and_preserves_reasons():
    decision = evaluate_generation_safety(
        ExtractionResult(
            canonical_ir=_ir(),
            generation_safe=False,
            blocking_reasons=["unsupported source feature"],
        ),
        _ir(),
    )

    assert decision.allowed is False
    assert decision.blocking_reasons == ["unsupported source feature"]


def test_unsafe_ir_blocks_and_manual_review_does_not_block_by_itself():
    decision = evaluate_generation_safety(
        ExtractionResult(canonical_ir=_ir(), requires_manual_review=True),
        _ir(
            generation_safe=False,
            generation_blocking_reasons=["unsafe IR"],
        ),
    )

    assert decision.allowed is False
    assert decision.requires_manual_review is True
    assert decision.blocking_reasons == ["unsafe IR"]

    review_only = evaluate_generation_safety(
        ExtractionResult(canonical_ir=_ir(), requires_manual_review=True),
        _ir(),
    )
    assert review_only.allowed is True
    assert review_only.requires_manual_review is True


def test_missing_ir_blocks():
    decision = evaluate_generation_safety(None, None)

    assert decision.allowed is False
    assert "Canonical IR is unavailable." in decision.blocking_reasons


def test_conflicting_blocking_reasons_fail_closed_even_when_boolean_is_true():
    decision = MigrationSafetyEvaluator().evaluate_pre_generation(
        ExtractionResult(
            canonical_ir=_ir(),
            generation_safe=True,
            blocking_reasons=["unsupported dependency"],
        ),
        _ir(
            generation_safe=True,
            generation_blocking_reasons=["unsafe route"],
        ),
    )

    assert decision.allowed is False
    assert decision.blocking_reasons == ["unsupported dependency", "unsafe route"]
    assert decision.stage == "pre_generation"
    assert {issue.code for issue in decision.issues} == {
        "EXTRACTION_BLOCKING_REASON",
        "IR_BLOCKING_REASON",
    }


def test_manual_review_and_incomplete_extraction_are_not_implicit_blocks():
    decision = MigrationSafetyEvaluator().evaluate_extraction(
        ExtractionResult(
            canonical_ir=_ir(),
            migration_complete=False,
            requires_manual_review=True,
        )
    )

    assert decision.allowed is True
    assert decision.requires_manual_review is True
    assert decision.warnings == ["Source extraction is incomplete; review source accounting."]
    assert decision.stage == "post_extraction"


def test_external_blocking_issue_is_aggregated_without_reimplementing_validation():
    decision = MigrationSafetyEvaluator().evaluate_pre_generation(
        ExtractionResult(canonical_ir=_ir()),
        _ir(),
        validation_result=[SimpleNamespace(
            severity="HIGH",
            blocking=True,
            message="Missing referenced service",
            category="DEPENDENCY",
        )],
    )

    assert decision.allowed is False
    assert decision.blocking_reasons == ["Missing referenced service"]
    assert decision.issues[-1].source == "DEPENDENCY"
