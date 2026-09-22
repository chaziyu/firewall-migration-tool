"""Shared source-accounting models used by vendor-native pipelines."""

from fwmigrate.extraction.models import (
    ExtractionStatus,
    MigrationImpact,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)

__all__ = [
    "ExtractionStatus",
    "MigrationImpact",
    "SourceCommand",
    "SourceInventoryItem",
    "SourceSectionResult",
    "UnsupportedItem",
]
