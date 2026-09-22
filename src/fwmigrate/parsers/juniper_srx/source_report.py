"""Compatibility exports for the vendor-native Juniper source reporter."""

from fwmigrate.vendors.juniper_srx.source_report import *
from fwmigrate.vendors.juniper_srx.source_report import (
    JuniperSRXSourceReporter,
    JuniperSourceResult,
    extract_juniper_source,
)

__all__ = ["JuniperSRXSourceReporter", "JuniperSourceResult", "extract_juniper_source"]
