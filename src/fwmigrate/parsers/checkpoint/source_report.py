"""Compatibility facade for vendor-native Check Point reporting."""

from fwmigrate.vendors.checkpoint.source_report import *
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
