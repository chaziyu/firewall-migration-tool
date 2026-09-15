from types import SimpleNamespace

from fwmigrate.application.safety import evaluate_generation_safety


def test_safety_allows_clean_extraction_and_ir():
    decision = evaluate_generation_safety(
        SimpleNamespace(
            canonical_ir=object(),
            generation_safe=True,
            blocking_reasons=[],
            requires_manual_review=False,
        ),
        SimpleNamespace(
            generation_safe=True,
            generation_blocking_reasons=[],
            requires_manual_review=False,
        ),
    )

    assert decision.allowed is True
    assert decision.blocking_reasons == []
    assert decision.requires_manual_review is False


def test_safety_deduplicates_blocking_reasons():
    decision = evaluate_generation_safety(
        SimpleNamespace(
            generation_safe=False,
            blocking_reasons=["unsafe", "unsafe"],
            requires_manual_review=True,
            canonical_ir=object(),
        ),
        SimpleNamespace(
            generation_safe=False,
            generation_blocking_reasons=["unsafe", "malformed"],
            requires_manual_review=False,
        ),
    )

    assert decision.allowed is False
    assert decision.blocking_reasons == ["unsafe", "malformed"]
    assert decision.requires_manual_review is True


def test_safety_blocks_contradictory_safe_flags():
    decision = evaluate_generation_safety(
        SimpleNamespace(
            canonical_ir=object(),
            generation_safe=True,
            blocking_reasons=["source contradiction"],
            requires_manual_review=False,
        ),
        SimpleNamespace(
            generation_safe=True,
            generation_blocking_reasons=["IR contradiction"],
            requires_manual_review=False,
        ),
    )

    assert decision.allowed is False
    assert decision.blocking_reasons == ["source contradiction", "IR contradiction"]
