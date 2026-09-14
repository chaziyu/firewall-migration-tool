from dataclasses import dataclass, field
from typing import List, Optional

from fwmigrate.ir.config import IRConfig
from fwmigrate.ir.enums import MigrationConfidence, PolicyAction
from fwmigrate.ir.metadata import IRAuditEntry


@dataclass(frozen=True)
class NormalizationChange:
    code: str
    object_type: str
    object_id: str
    description: str
    before_summary: str
    after_summary: str
    requires_manual_review: bool = False


@dataclass
class NormalizationResult:
    ir: IRConfig
    changes: List[NormalizationChange] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requires_manual_review: bool = False
    blocking_issues: List[str] = field(default_factory=list)


class IRNormalizer:
    """Apply mandatory, target-independent semantic corrections."""

    def __init__(self, ir: Optional[IRConfig] = None):
        self.ir = ir

    def normalize(self, ir: Optional[IRConfig] = None) -> NormalizationResult:
        target = ir if ir is not None else self.ir
        if target is None:
            raise ValueError("IRNormalizer requires an IRConfig to normalize.")
        self.ir = target
        result = NormalizationResult(ir=target)
        self._normalize_outbound_threat_source_anomalies(result)
        return result

    def normalize_outbound_threat_source_anomalies(
        self,
        ir: Optional[IRConfig] = None,
    ) -> NormalizationResult:
        target = ir if ir is not None else self.ir
        if target is None:
            raise ValueError("IRNormalizer requires an IRConfig to normalize.")
        self.ir = target
        result = NormalizationResult(ir=target)
        self._normalize_outbound_threat_source_anomalies(result)
        return result

    def _normalize_outbound_threat_source_anomalies(
        self,
        result: NormalizationResult,
    ) -> None:
        for pol in result.ir.policies:
            if (
                pol.requires_manual_review
                or pol.migration_status != "NORMALIZED"
                or not pol.safe_for_target_generation
            ):
                continue
            if pol.action == PolicyAction.DENY and len(pol.source) == 1 and len(pol.destination) >= 5:
                src_val = pol.source[0]
                if src_val not in ["all", "any"] and any(
                    "botnet" in a.lower()
                    or "emotet" in a.lower()
                    or "bad" in a.lower()
                    or "malicious" in a.lower()
                    for a in pol.destination
                ):
                    before = f"source={src_val!r}; destination_count={len(pol.destination)}"
                    pol.source = ["any"]
                    if src_val not in pol.destination:
                        pol.destination.append(src_val)
                    after = f"source='any'; destination_count={len(pol.destination)}"
                    description = (
                        f"Moved outbound threat source object '{src_val}' to the "
                        "destination references based on the deterministic anomaly rule."
                    )
                    result.changes.append(NormalizationChange(
                        code="OUTBOUND_THREAT_SOURCE_REWRITE",
                        object_type="security_rule",
                        object_id=pol.name,
                        description=description,
                        before_summary=before,
                        after_summary=after,
                    ))
                    result.ir.audit_entries.append(IRAuditEntry(
                        id=pol.name,
                        category="Policy Optimization",
                        message=(
                            f"Automatically fixed source field anomaly in outbound block rule "
                            f"'{pol.name}': Changed source from '{src_val}' to 'any' and ensured "
                            f"'{src_val}' is in the destination list."
                        ),
                        confidence=MigrationConfidence.FULL,
                    ))


class RuleNormalizer(IRNormalizer):
    """Compatibility name for callers that used the original normalizer."""


__all__ = [
    "IRNormalizer",
    "NormalizationChange",
    "NormalizationResult",
    "RuleNormalizer",
]
