"""Pair-owned Juniper SRX planning records."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SRXMigrationDecision:
    key: str
    source_vdom: str | None
    source_kind: str
    source_name: str
    target_field: str
    label: str
    mode: str = "REQUIRED"
    value: Any = None
    review_state: str = "PENDING"
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SRXFinding:
    code: str
    message: str
    source_vdom: str | None = None
    source_kind: str | None = None
    source_name: str | None = None
    blocking: bool = True


@dataclass(frozen=True, slots=True)
class SRXPlanItem:
    key: str
    family: str
    source_vdom: str
    source_name: str
    target_name: str
    settings: tuple[tuple[str, Any], ...] = ()
    dependencies: tuple[str, ...] = ()
    decision_keys: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    source_order: int = 0
    approval_group: str | None = None
    target_disposition: str | None = None

    @property
    def disposition(self) -> str:
        return "BLOCK" if self.blockers else self.target_disposition or "CREATE"


@dataclass(frozen=True, slots=True)
class SRXMigrationPlan:
    source_vdom: str | None
    target_context: str | None
    target_version: str | None
    target_mode: str | None
    routing_table: str | None
    items: tuple[SRXPlanItem, ...]
    decisions: tuple[SRXMigrationDecision, ...]
    findings: tuple[SRXFinding, ...]

    @property
    def blocked(self) -> bool:
        return any(finding.blocking for finding in self.findings) or any(item.blockers for item in self.items)
