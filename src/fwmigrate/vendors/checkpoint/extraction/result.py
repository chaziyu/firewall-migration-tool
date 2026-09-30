from __future__ import annotations

from dataclasses import dataclass, field

from ..models import CheckPointCollectionDiagnostic, ScopeSelectionResult
from ..model.common import CheckPointSourceObject
from ..model.source import CheckPointConfig
from .source_inventory import CheckPointSourceRecord
from .source_metadata import CheckPointSourceMetadata


@dataclass(frozen=True, slots=True)
class CPPolicyContextRecord:
    source: CheckPointSourceObject
    section_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExtractionResult:
    config: CheckPointConfig
    collection: tuple[CheckPointCollectionDiagnostic, ...] = ()
    source_objects: tuple[CheckPointSourceRecord, ...] = ()
    source_metadata: CheckPointSourceMetadata = field(default_factory=CheckPointSourceMetadata)
    policy_context: tuple[CPPolicyContextRecord, ...] = ()
    scope: ScopeSelectionResult = field(default_factory=ScopeSelectionResult)

    @property
    def source_inventory(self) -> tuple[CheckPointSourceRecord, ...]:
        """Compatibility name for the source-object inventory."""
        return self.source_objects
