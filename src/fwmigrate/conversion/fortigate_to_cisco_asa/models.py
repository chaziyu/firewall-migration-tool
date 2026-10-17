"""Pair-owned FortiGate to ASA planning records."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ASAMigrationDecision:
    key: str
    source_vdom: str | None
    source_kind: str
    source_name: str
    target_field: str
    label: str
    value: Any = None
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAFinding:
    code: str
    message: str
    source_vdom: str | None = None
    source_kind: str | None = None
    source_name: str | None = None
    blocking: bool = True


@dataclass(frozen=True, slots=True)
class ASAPlanItem:
    key: str
    family: str
    source_vdom: str
    source_name: str
    target_name: str
    settings: tuple[tuple[str, Any], ...] = ()
    dependencies: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    source_order: int = 0
    target_disposition: str | None = None

    @property
    def disposition(self) -> str:
        return "BLOCK" if self.blockers else self.target_disposition or "CREATE"


@dataclass(frozen=True, slots=True)
class ASAMigrationPlan:
    source_vdom: str | None
    target_context: str | None
    target_version: str | None
    target_mode: str | None
    items: tuple[ASAPlanItem, ...]
    decisions: tuple[ASAMigrationDecision, ...]
    findings: tuple[ASAFinding, ...]

    @property
    def blocked(self) -> bool:
        return any(finding.blocking for finding in self.findings) or any(item.blockers for item in self.items)
