"""Reserved boundary for future pair-specific configuration converters.

Source reporting does not import this package. No converter is implemented.
"""

from .contracts import (
    PairConverter,
    TargetRenderer,
    TargetValidator,
    TargetVendorConfig,
    VendorDerivedViews,
    VendorSourceConfig,
)
from .registry import ConversionRegistry

__all__ = [
    "ConversionRegistry",
    "PairConverter",
    "TargetRenderer",
    "TargetValidator",
    "TargetVendorConfig",
    "VendorDerivedViews",
    "VendorSourceConfig",
]
