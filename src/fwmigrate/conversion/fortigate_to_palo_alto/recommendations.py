"""Read-only FortiGate to PAN-OS migration recommendations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any, Iterable

from .decisions import PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key


class PANRecommendationMethod(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    TARGET_EVIDENCE = "TARGET_EVIDENCE"
    AI_ASSISTED = "AI_ASSISTED"


class PANRecommendationConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


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
            "evidence": list(self.evidence),
            "candidate_target_objects": list(self.candidate_target_objects),
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


def target_device(item: Any) -> str | None:
    scope = getattr(item, "scope", None)
    return (scope.device_serial or scope.device_name) if scope else None


def target_objects(target: Any, attribute: str, device: str | None = None) -> tuple[Any, ...]:
    if target is None:
        return ()
    return tuple(item for item in getattr(target.config, attribute, ()) if device is None or target_device(item) == device)


def target_names(target: Any, attribute: str, device: str | None = None) -> tuple[str, ...]:
    return tuple(sorted({str(item.name) for item in target_objects(target, attribute, device) if getattr(item, "name", None)}))


def decision_key_if_present(decisions: PANMigrationDecisionSet | None, vdom: str, kind: str, name: str, field: str) -> str | None:
    key = make_decision_key(vdom, kind, name, field)
    return key if decisions and any(item.key == key for item in decisions.decisions) else None


def decision_value(decisions: PANMigrationDecisionSet | None, key: str | None) -> str | None:
    if not decisions or not key:
        return None
    for item in decisions.decisions:
        if item.key == key and (item.mode.value == "AUTO" or item.review_state is PANDecisionReviewState.CONFIRMED):
            return item.value
    return None


def method_for_candidates(candidates: Iterable[str]) -> PANRecommendationMethod:
    return PANRecommendationMethod.TARGET_EVIDENCE if tuple(candidates) else PANRecommendationMethod.DETERMINISTIC


def unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))
