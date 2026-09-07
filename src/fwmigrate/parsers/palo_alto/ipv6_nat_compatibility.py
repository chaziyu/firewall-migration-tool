"""Backward-compatible review markers for PAN-OS IPv6 NAT semantics."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .source_model import PANScope
from .xml_utils import text_or_none


class PANOSIPv6NATCompatibilityMixin:
    """Retain legacy NAT64/NPTv6 review markers alongside Phase 3 semantics.

    Phase 3 adds precise family validation and the generic
    ``source-specific-ipv6-nat-target-semantics`` marker. Existing consumers and
    regression tests also rely on the historical family-specific markers, so
    keep those stable as compatibility aliases rather than removing them.
    """

    @staticmethod
    def _compat_nat_family(entry: ET.Element):
        node = entry.find("./nat-type")
        value = text_or_none(entry, "./nat-type")
        if value:
            return value.strip().lower()
        if node is not None and len(node) == 1:
            return next(iter(node)).tag.strip().lower()
        return None

    def _enhance_nat_rule(self, scope: PANScope, entry: ET.Element, extraction, rule) -> None:
        super()._enhance_nat_rule(scope, entry, extraction, rule)

        family = self._compat_nat_family(entry)
        if family not in {"nat64", "nptv6"}:
            return

        legacy_reason = f"{family}-source-semantics"
        if legacy_reason not in rule.review_reasons:
            rule.review_reasons.append(legacy_reason)

        rule.review_reasons = list(dict.fromkeys(rule.review_reasons))
        rule.requires_manual_review = bool(rule.review_reasons)
        rule.migration_status = (
            "PARTIALLY_NORMALIZED" if rule.review_reasons else "NORMALIZED"
        )

        item = self._inventory_item(extraction, "nat", scope, entry.get("name"))
        if item is not None:
            item.source_attributes.update(rule.source_attributes)
            item.requires_manual_review = rule.requires_manual_review
            if legacy_reason not in item.notes:
                item.notes.append(
                    f"Compatibility review marker retained: {legacy_reason}."
                )
