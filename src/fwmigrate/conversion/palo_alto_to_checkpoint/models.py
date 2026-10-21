"""Pair-owned Check Point migration records."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CPMigrationDecision:
    key: str
    source_scope: str | None
    source_kind: str
    source_name: str
    target_field: str
    label: str
    value: Any = None
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CPFinding:
    code: str
    message: str
    source_scope: str | None = None
    source_kind: str | None = None
    source_name: str | None = None
    blocking: bool = True


@dataclass(frozen=True, slots=True)
class CPMigrationItem:
    key: str
    family: str
    source_scope: str
    source_name: str
    target_name: str
    settings: tuple[tuple[str, Any], ...] = ()
    dependencies: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    source_order: int = 0
    target_disposition: str | None = None
    source_path: str = ""
    source_kind: str = ""


@dataclass(frozen=True, slots=True)
class CPMigrationPlan:
    source_scope: str | None
    options: dict[str, Any]
    items: tuple[CPMigrationItem, ...]
    decisions: tuple[CPMigrationDecision, ...]
    findings: tuple[CPFinding, ...]

