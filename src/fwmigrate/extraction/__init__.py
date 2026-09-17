"""Vendor-neutral source extraction accounting models."""

from fwmigrate.extraction.finalize import finalize_extraction
from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    MigrationImpact,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)

__all__ = [
    "ExtractionResult",
    "ExtractionStatus",
    "MigrationImpact",
    "SourceCommand",
    "SourceInventoryItem",
    "SourceSectionResult",
    "UnsupportedItem",
    "finalize_extraction",
]
