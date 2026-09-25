"""Pair-specific engineer review state for FortiGate to PAN-OS mappings."""

from dataclasses import asdict, dataclass, replace
from enum import Enum
import json
from typing import Any

from .options import InterfaceMapping, PANMigrationOptions, VDOMMapping


class PANDecisionMode(str, Enum):
    AUTO = "AUTO"
    SUGGESTED = "SUGGESTED"
    REQUIRED = "REQUIRED"
    UNSUPPORTED = "UNSUPPORTED"


class PANDecisionReviewState(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"


def make_decision_key(source_vdom: str, source_kind: str, source_name: str, target_field: str) -> str:
    return json.dumps([source_vdom, source_kind, source_name, target_field], ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class PANMigrationDecision:
    source_vdom: str
    source_kind: str
    source_name: str
    target_field: str
    suggested_value: Any = None
    value: Any = None
    mode: PANDecisionMode = PANDecisionMode.REQUIRED
    review_state: PANDecisionReviewState = PANDecisionReviewState.PENDING
    reason: str = ""
    affected_count: int = 0
    affected_by: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in (self.source_vdom, self.source_kind, self.source_name, self.target_field)):
            raise ValueError("decision identity fields must be non-empty strings")
        allowed = {"vdom": {"vsys", "virtual_router"}, "interface": {"target_interface", "target_zone"}, "zone": {"target_zone"}}
        if self.source_kind not in allowed or self.target_field not in allowed[self.source_kind]:
            raise ValueError("decision source kind and target field are incompatible")
        if self.suggested_value is not None and not isinstance(self.suggested_value, str):
            raise ValueError("suggested_value must be a string or null")
        if self.value is not None and not isinstance(self.value, str):
            raise ValueError("value must be a string or null")
        if not isinstance(self.mode, PANDecisionMode) or not isinstance(self.review_state, PANDecisionReviewState):
            raise ValueError("decision mode or review state is invalid")
        if not isinstance(self.affected_count, int) or self.affected_count < 0:
            raise ValueError("affected_count must be a non-negative integer")
        if self.affected_by is not None and any(
            not isinstance(category, str) or not isinstance(count, int) or count < 0
            for category, count in self.affected_by.items()
        ):
            raise ValueError("affected_by must contain non-negative integer counts")

    @property
    def key(self) -> str:
        return make_decision_key(self.source_vdom, self.source_kind, self.source_name, self.target_field)

    def confirm(self, value: Any = None) -> "PANMigrationDecision":
        return replace(self, value=self.value if value is None else value, review_state=PANDecisionReviewState.CONFIRMED)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["mode"] = self.mode.value
        result["review_state"] = self.review_state.value
        result["key"] = self.key
        result["affected_by"] = dict(self.affected_by or {})
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PANMigrationDecision":
        if not isinstance(value, dict):
            raise ValueError("each decision must be an object")
        data = {key: item for key, item in value.items() if key != "key"}
        data["mode"] = PANDecisionMode(data.get("mode", PANDecisionMode.REQUIRED))
        data["review_state"] = PANDecisionReviewState(data.get("review_state", PANDecisionReviewState.PENDING))
        data["affected_by"] = dict(data.get("affected_by") or {})
        decision = cls(**data)
        if value.get("key", decision.key) != decision.key:
            raise ValueError("decision key does not match its identity")
        return decision


@dataclass(frozen=True, slots=True)
class PANMigrationDecisionSet:
    decisions: tuple[PANMigrationDecision, ...] = ()

    def __post_init__(self) -> None:
        if len({decision.key for decision in self.decisions}) != len(self.decisions):
            raise ValueError("decision keys must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {"decisions": [decision.to_dict() for decision in self.decisions]}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PANMigrationDecisionSet":
        if not isinstance(value, dict) or not isinstance(value.get("decisions", ()), list):
            raise ValueError("decisions must be an array")
        return cls(tuple(PANMigrationDecision.from_dict(item) for item in value.get("decisions", ())))

    def to_options(self) -> PANMigrationOptions:
        vdoms: dict[str, dict[str, str]] = {}
        interfaces: dict[str, dict[str, dict[str, str]]] = {}
        for decision in self.decisions:
            usable = decision.mode == PANDecisionMode.AUTO or decision.review_state == PANDecisionReviewState.CONFIRMED
            if not usable or decision.mode == PANDecisionMode.UNSUPPORTED or not decision.value:
                continue
            if decision.source_kind == "vdom":
                vdoms.setdefault(decision.source_vdom, {})[decision.target_field] = decision.value
            else:
                interfaces.setdefault(decision.source_vdom, {}).setdefault(decision.source_name, {})[decision.target_field] = decision.value
        return PANMigrationOptions(
            vdoms={name: VDOMMapping(**values) for name, values in vdoms.items()},
            interfaces={vdom: {name: InterfaceMapping(**values) for name, values in items.items()} for vdom, items in interfaces.items()},
        )


def build_decision_set(config, derived, requirements, previous=None) -> PANMigrationDecisionSet:
    """Create deterministic mapping suggestions and carry forward confirmed values."""
    from .requirements import build_mapping_requirements

    requirements = requirements or build_mapping_requirements(config, derived)
    previous_by_key = {item.key: item for item in getattr(previous, "decisions", ())}
    zones_by_vdom: dict[str, list[str]] = {}
    for zone in getattr(config, "zones", ()):
        if zone.name:
            zones_by_vdom.setdefault(zone.vdom or "root", []).append(zone.name)
    decisions = []

    def add(vdom, kind, name, field, *, suggestion=None, mode=PANDecisionMode.REQUIRED, reason="", impact=None):
        decision = PANMigrationDecision(
            source_vdom=vdom, source_kind=kind, source_name=name, target_field=field,
            suggested_value=suggestion, value=suggestion if mode == PANDecisionMode.AUTO else None,
            mode=mode, reason=reason, affected_count=(impact or {}).get("affected_count", 0),
            affected_by=(impact or {}).get("affected_by", {}),
        )
        old = previous_by_key.get(decision.key)
        if old and old.review_state == PANDecisionReviewState.CONFIRMED:
            decision = replace(old, affected_count=decision.affected_count, affected_by=decision.affected_by)
        decisions.append(decision)

    for item in requirements.get("vdoms", ()):
        vdom = item["source_vdom"]
        for field in item.get("requires", ()):
            add(vdom, "vdom", vdom, field, reason="explicit target mapping required")
    for item in requirements.get("interfaces", ()):
        vdom, name, kind = item["source_vdom"], item["source_name"], item["kind"]
        fields = item.get("requires", ())
        for field in fields:
            suggestion, mode = None, PANDecisionMode.REQUIRED
            reason = "explicit target mapping required"
            if field == "target_zone" and kind == "zone":
                suggestion, mode = name, PANDecisionMode.SUGGESTED
                reason = "same-name FortiGate zone suggestion"
            elif field == "target_zone" and kind == "interface":
                memberships = sorted(set(zones_by_vdom.get(vdom, ())) & {
                    zone.name for zone in getattr(config, "zones", ())
                    if (zone.vdom or "root") == vdom and name in (zone.members or ())
                })
                if len(memberships) == 1:
                    suggestion, mode = memberships[0], PANDecisionMode.SUGGESTED
                    reason = "interface belongs to one explicit FortiGate zone"
            impact = item
            add(vdom, kind, name, field, suggestion=suggestion, mode=mode, reason=reason, impact=impact)
    return PANMigrationDecisionSet(tuple(sorted(decisions, key=lambda item: item.key)))
