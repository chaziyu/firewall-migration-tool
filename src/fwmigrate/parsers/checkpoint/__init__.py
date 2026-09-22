"""Compatibility facade for native Check Point source reporting."""

from fwmigrate.vendors.checkpoint.source_report import (
    CheckPointSourceReporter,
    CheckPointSourceResult,
    extract_checkpoint_source,
)

__all__ = [
    "CheckPointSourceReporter",
    "CheckPointSourceResult",
    "extract_checkpoint_source",
]
