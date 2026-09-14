"""Stable common IR imports; ``core`` remains the compatibility source."""

from fwmigrate.ir.core import IRMetadata
from fwmigrate.ir.enums import *

__all__ = [
    "IRMetadata",
    "AddressType",
    "ServiceProtocol",
    "PolicyAction",
    "NATType",
    "NATTranslationMode",
    "NATFamily",
    "IRRouteNextHopType",
    "MigrationConfidence",
]
