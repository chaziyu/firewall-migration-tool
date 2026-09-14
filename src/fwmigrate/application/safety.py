from dataclasses import dataclass, field
from typing import Any, Iterable, List, Optional

from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig


@dataclass(frozen=True)
class SafetyIssue:
    code: str
    message: str
    stage: str
    severity: str = "blocking"
    object_type: Optional[str] = None
    object_id: Optional[str] = None
    source: Optional[str] = None


@dataclass
class SafetyDecision:
    allowed: bool
    blocking_reasons: List[str] = field(default_factory=list)
    requires_manual_review: bool = False
    warnings: List[str] = field(default_factory=list)
    stage: str = "pre_generation"
    issues: List[SafetyIssue] = field(default_factory=list)


def _external_issues(value: Any, stage: str, prefix: str) -> List[SafetyIssue]:
    if value is None:
        return []
    value = getattr(value, "issues", value)
    if isinstance(value, (str, bytes)):
        value = [value]
    elif not isinstance(value, Iterable):
        value = [value]

    issues = []
    for index, item in enumerate(value):
        if isinstance(item, SafetyIssue):
            issues.append(item if item.stage == stage else SafetyIssue(
                code=item.code,
                message=item.message,
                stage=stage,
                severity=item.severity,
                object_type=item.object_type,
                object_id=item.object_id,
                source=item.source,
            ))
            continue
        message = str(getattr(item, "message", item))
        severity = str(getattr(item, "severity", "warning")).lower()
        category = str(getattr(item, "category", "")).lower()
        blocking = bool(getattr(item, "blocking", False)) or severity in {
            "blocking", "critical"
        }
        if not blocking and category in {"manual_review", "manual review"}:
            severity = "manual_review"
        issues.append(SafetyIssue(
            code=str(getattr(item, "code", None) or f"{prefix}_{index}"),
            message=message,
            stage=stage,
            severity="blocking" if blocking else severity,
            object_type=getattr(item, "object_type", None),
            object_id=getattr(item, "object_id", None) or getattr(item, "source_object", None),
            source=getattr(item, "source", None) or getattr(item, "category", None),
        ))
    return issues


class MigrationSafetyEvaluator:
    """Make the application-level decision before deployable generation."""

    def evaluate_extraction(self, extraction: Optional[ExtractionResult]) -> SafetyDecision:
        issues: List[SafetyIssue] = []
        manual_review = bool(extraction and extraction.requires_manual_review)
        warnings: List[str] = []
        if extraction is None:
            issues.append(SafetyIssue(
                "MISSING_EXTRACTION", "Extraction result is unavailable.", "post_extraction"
            ))
        else:
            if extraction.canonical_ir is None:
                issues.append(SafetyIssue(
                    "MISSING_CANONICAL_IR", "Canonical IR is unavailable.", "post_extraction"
                ))
            if not extraction.migration_complete:
                warnings.append("Source extraction is incomplete; review source accounting.")
            if not extraction.generation_safe:
                reasons = extraction.blocking_reasons or [
                    "Source extraction marked generation unsafe."
                ]
                issues.extend(SafetyIssue(
                    "EXTRACTION_UNSAFE", reason, "post_extraction", source="extraction"
                ) for reason in reasons)
            elif extraction.blocking_reasons:
                issues.extend(SafetyIssue(
                    "EXTRACTION_BLOCKING_REASON", reason, "post_extraction", source="extraction"
                ) for reason in extraction.blocking_reasons)
        return self._decision("post_extraction", issues, manual_review, warnings)

    def evaluate_ir(self, ir: Optional[IRConfig]) -> SafetyDecision:
        issues: List[SafetyIssue] = []
        manual_review = bool(ir and ir.requires_manual_review)
        if ir is None:
            issues.append(SafetyIssue(
                "MISSING_CANONICAL_IR", "Canonical IR is unavailable.", "pre_generation"
            ))
        else:
            if not ir.generation_safe:
                reasons = ir.generation_blocking_reasons or [
                    "Canonical IR marked generation unsafe."
                ]
                issues.extend(SafetyIssue(
                    "IR_UNSAFE", reason, "pre_generation", source="ir"
                ) for reason in reasons)
            elif ir.generation_blocking_reasons:
                issues.extend(SafetyIssue(
                    "IR_BLOCKING_REASON", reason, "pre_generation", source="ir"
                ) for reason in ir.generation_blocking_reasons)
        return self._decision("pre_generation", issues, manual_review)

    def evaluate_pre_generation(
        self,
        extraction: Optional[ExtractionResult],
        ir: Optional[IRConfig],
        validation_result: Any = None,
        capability_result: Any = None,
    ) -> SafetyDecision:
        extraction_decision = self.evaluate_extraction(extraction)
        ir_decision = self.evaluate_ir(ir)
        issues = [*extraction_decision.issues, *ir_decision.issues]
        issues.extend(_external_issues(validation_result, "pre_generation", "VALIDATION"))
        issues.extend(_external_issues(capability_result, "pre_generation", "CAPABILITY"))
        return self._decision(
            "pre_generation",
            issues,
            extraction_decision.requires_manual_review or ir_decision.requires_manual_review,
            [*extraction_decision.warnings, *ir_decision.warnings],
        )

    @staticmethod
    def _decision(
        stage: str,
        issues: List[SafetyIssue],
        manual_review: bool,
        warnings: Optional[List[str]] = None,
    ) -> SafetyDecision:
        blocking = [issue.message for issue in issues if issue.severity == "blocking"]
        warning_messages = list(warnings or []) + [
            issue.message for issue in issues if issue.severity != "blocking"
        ]
        return SafetyDecision(
            allowed=not blocking,
            blocking_reasons=list(dict.fromkeys(blocking)),
            requires_manual_review=manual_review or any(
                issue.severity in {"manual_review", "review"} for issue in issues
            ),
            warnings=list(dict.fromkeys(warning_messages)),
            stage=stage,
            issues=issues,
        )


def evaluate_generation_safety(
    extraction: Optional[ExtractionResult],
    ir: Optional[IRConfig],
) -> SafetyDecision:
    """Backward-compatible facade for callers that only need the final gate."""
    return MigrationSafetyEvaluator().evaluate_pre_generation(extraction, ir)
