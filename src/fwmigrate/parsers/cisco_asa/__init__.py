"""Compatibility facade for native Cisco ASA source reporting."""

from fwmigrate.vendors.cisco_asa.source_report import (
    ASASourceResult,
    CiscoASASourceReporter,
    extract_cisco_asa_source,
)

__all__ = [
    "ASASourceResult",
    "CiscoASASourceReporter",
    "extract_cisco_asa_source",
]
