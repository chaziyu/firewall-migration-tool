"""Vendor-native source collection."""

from .contracts import CollectionError, CollectionPart, CollectionStatus, CollectedSource, SourceCollector
from .registry import SourceCollectorRegistry, source_collectors

__all__ = ["CollectionError", "CollectionPart", "CollectionStatus", "CollectedSource", "SourceCollector", "SourceCollectorRegistry", "source_collectors"]
