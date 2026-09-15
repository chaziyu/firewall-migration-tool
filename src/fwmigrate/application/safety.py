from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir import IRConfig


@dataclass
class SafetyDecision:
    allowed: bool
    blocking_reasons: List[str] = field(default_factory=list)
    requires_manual_review: bool = False


def evaluate_generation_safety(
    extraction: Optional[ExtractionResult],
    ir: Optional[IRConfig],
    validation_blocking_reasons: Sequence[str] = (),
) -> SafetyDecision:
    reasons: List[str] = []
    if extraction is None:
        reasons.append("Extraction result is unavailable.")
    elif not extraction.generation_safe or extraction.blocking_reasons:
        reasons.extend(extraction.blocking_reasons)
        if not extraction.blocking_reasons:
            reasons.append("Source extraction marked generation unsafe.")

    if ir is None:
        reasons.append("Canonical IR is unavailable.")
    elif not ir.generation_safe or ir.generation_blocking_reasons:
        reasons.extend(ir.generation_blocking_reasons)
        if not ir.generation_blocking_reasons:
            reasons.append("Canonical IR marked generation unsafe.")

    reasons.extend(validation_blocking_reasons)

    unique_reasons = list(dict.fromkeys(reasons))
    return SafetyDecision(
        allowed=not unique_reasons,
        blocking_reasons=unique_reasons,
        requires_manual_review=bool(
            (extraction and extraction.requires_manual_review)
            or (ir and ir.requires_manual_review)
        ),
    )
