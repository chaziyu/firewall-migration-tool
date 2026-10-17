"""FortiOS-specific planned CLI configuration; never an extracted source model."""
from dataclasses import asdict, dataclass
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class FGPlannedItem:
    key: str
    family: str
    source_scope: str
    source_name: str
    source_path: str
    target_name: str
    target_vdom: str
    section: str
    settings: tuple[tuple[str, tuple[str, ...]], ...] = ()
    dependencies: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    disposition: str = "CREATE"
    global_scope: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FGMigrationPlan:
    items: tuple[FGPlannedItem, ...] = ()
    findings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FGRenderedMigration:
    commands: tuple[str, ...]
    report: dict

    @property
    def text(self):
        return "\n".join(self.commands)
