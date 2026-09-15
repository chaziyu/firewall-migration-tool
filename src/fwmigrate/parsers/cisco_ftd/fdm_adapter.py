from __future__ import annotations

from fwmigrate.parsers.cisco_ftd.fdm_bundle import (
    CiscoFDMBundleParser as _RawCiscoFDMBundleParser,
    FDM_BUNDLE_FORMAT,
    is_fdm_bundle,
)


class CiscoFDMBundleParser(_RawCiscoFDMBundleParser):
    """Apply fail-closed generation gates to the structured FDM parser."""

    def parse(self):
        ir = super().parse()
        if self._unresolved or any(rule.requires_manual_review for rule in ir.nat_rules):
            ir.generation_safe = False
            reason = "FDM policy/NAT semantics require manual target validation"
            if reason not in ir.generation_blocking_reasons:
                ir.generation_blocking_reasons.append(reason)
        return ir


__all__ = ["CiscoFDMBundleParser", "FDM_BUNDLE_FORMAT", "is_fdm_bundle"]
