"""Pair-owned PAN-OS to Cisco ASA plan records."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ASAPlanItem:
    key: str
    family: str
    source_scope: str
    source_kind: str
    source_name: str
    source_path: str
    target_name: str
    settings: tuple[tuple[str, Any], ...] = ()
    dependencies: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    source_order: int = 0
    target_disposition: str | None = None
    approval_group: str | None = None

    @property
    def disposition(self) -> str:
        return "BLOCK" if self.blockers else self.target_disposition or "CREATE"


@dataclass(frozen=True, slots=True)
class ASAMigrationPlan:
    source_scope: str | None
    target_context: str
    target_version: str
    items: tuple[ASAPlanItem, ...]
    findings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASARenderedMigration:
    commands: tuple[str, ...]
    command_sha256: str
    blocked_items: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def command_count(self):
        return len(self.commands)

    @property
    def command_text(self):
        return "\n".join(self.commands) + ("\n" if self.commands else "")
