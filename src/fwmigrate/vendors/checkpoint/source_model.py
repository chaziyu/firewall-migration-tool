"""Compatibility imports for the canonical Check Point source models."""

from .models import CheckPointCollectionDiagnostic
from .extraction.source_inventory import CheckPointSourceRecord
from .extraction.source_metadata import CheckPointSourceMetadata
from .model.source import CheckPointConfig
from .model.common import CheckPointSourceObject

__all__ = [
    "CheckPointCollectionDiagnostic",
    "CheckPointConfig",
    "CheckPointSourceMetadata",
    "CheckPointSourceObject",
    "CheckPointSourceRecord",
]
