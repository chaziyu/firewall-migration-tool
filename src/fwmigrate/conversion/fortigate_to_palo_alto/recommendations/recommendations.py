"""Read-only FortiGate to PAN-OS migration recommendations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any, Iterable

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet, make_decision_key, decision_value as decision_value
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_candidates import PANTargetCandidate, build_target_candidates, target_vsys_value


class PANRecommendationMethod(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    TARGET_EVIDENCE = "TARGET_EVIDENCE"


class PANRecommendationConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PANRecommendationReadiness(str, Enum):
    AUTO_SAFE = "AUTO_SAFE"
    SUGGEST = "SUGGEST"
    REQUIRES_DECISION = "REQUIRES_DECISION"
    MANUAL_DESIGN = "MANUAL_DESIGN"
    INCOMPLETE_EVIDENCE = "INCOMPLETE_EVIDENCE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class PANMigrationRecommendation:
    key: str
    family: str
    source_vdom: str
    source_kind: str
    source_name: str
    target_object_type: str
    title: str
    summary: str
    method: PANRecommendationMethod
    confidence: PANRecommendationConfidence
    evidence: tuple[str, ...] = ()
    candidate_target_objects: tuple[str, ...] = ()
    required_decision_keys: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    readiness: PANRecommendationReadiness | None = None
    target_candidates: tuple[PANTargetCandidate, ...] = ()

    def __post_init__(self) -> None:
        if self.readiness is not None and not isinstance(self.readiness, PANRecommendationReadiness):
            raise ValueError("recommendation readiness is invalid")
        if self.readiness is None:
            object.__setattr__(
                self,
                "readiness",
                PANRecommendationReadiness.MANUAL_DESIGN if self.blockers else PANRecommendationReadiness.SUGGEST,
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "family": self.family,
            "source_vdom": self.source_vdom,
            "source_kind": self.source_kind,
            "source_name": self.source_name,
            "target_object_type": self.target_object_type,
            "title": self.title,
            "summary": self.summary,
            "method": self.method.value,
            "confidence": self.confidence.value,
            "readiness": self.readiness.value,
            "evidence": list(self.evidence),
            "candidate_target_objects": list(self.candidate_target_objects),
            "target_candidates": [item.to_dict() for item in self.target_candidates],
            "required_decision_keys": list(self.required_decision_keys),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
        }


def recommendation_key(source_vdom: str, source_kind: str, source_name: str, target_object_type: str) -> str:
    return json.dumps([source_vdom, source_kind, source_name, target_object_type], ensure_ascii=False, separators=(",", ":"))


def source_value(item: Any, field: str) -> Any:
    """Return a field only when it is explicit in a source model."""
    value = getattr(item, field, None)
    if value in (None, "", []):
        return None
    explicit = getattr(item, "explicit_fields", ())
    if explicit and field not in explicit:
        return None
    return value


def source_facts(item: Any, fields: Iterable[str]) -> tuple[str, ...]:
    facts = []
    for field in fields:
        value = source_value(item, field)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            value = ", ".join(str(part) for part in value)
        facts.append(f"{field.replace('_', ' ')} = {value}")
    return tuple(facts)


def scoped_target_candidates(target: Any, attribute: str, family: str, source_name: str,
                             source_vdom: str, decisions: PANMigrationDecisionSet | None,
                             device: str | None, comparator=None, source_object=None) -> tuple[PANTargetCandidate, ...]:
    return build_target_candidates(
        target, attribute, family, source_name, device, target_vsys_value(decisions, source_vdom),
        comparator=comparator, source_object=source_object,
    )


def candidate_names(candidates: Iterable[PANTargetCandidate]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(candidate.name for candidate in candidates))


def decision_key_if_present(decisions: PANMigrationDecisionSet | None, vdom: str, kind: str, name: str, field: str) -> str | None:
    key = make_decision_key(vdom, kind, name, field)
    return key if decisions and any(item.key == key for item in decisions.decisions) else None


def unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))
