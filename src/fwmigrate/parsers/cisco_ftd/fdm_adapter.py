from __future__ import annotations

from fwmigrate.parsers.cisco_ftd.fdm_bundle import (
    CiscoFDMBundleParser as _RawCiscoFDMBundleParser,
    FDM_BUNDLE_FORMAT,
    is_fdm_bundle,
)


class CiscoFDMBundleParser(_RawCiscoFDMBundleParser):
    """Apply fail-closed generation gates to the structured FDM parser."""

    def parse(self):
        from .transformer import FDMToIRTransformer

        return FDMToIRTransformer(self).transform()


__all__ = ["CiscoFDMBundleParser", "FDM_BUNDLE_FORMAT", "is_fdm_bundle"]
