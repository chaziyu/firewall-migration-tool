from __future__ import annotations

from dataclasses import dataclass, field

from ..model.source import FGConfig
from .source_inventory import SourceObjectRecord
from .source_metadata import FortiGateSourceMetadata


@dataclass(slots=True)
class ExtractionResult:
    """Result of FortiGate source extraction."""

    config: FGConfig
    source_objects: tuple[SourceObjectRecord, ...] = field(
        default_factory=tuple
    )
    source_metadata: FortiGateSourceMetadata = field(
        default_factory=FortiGateSourceMetadata
    )
