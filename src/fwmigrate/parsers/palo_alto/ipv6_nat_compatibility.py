"""Backward-compatible review markers for incomplete PAN-OS IPv6 NAT semantics."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .source_model import PANScope
from .xml_utils import text_or_none


class PANOSIPv6NATCompatibilityMixin:
    """Retain legacy family markers only when Phase 3 semantics are incomplete.

    Fully validated NAT64/NPTv6 rules use the newer explicit semantic evidence
    and target-portability marker. Historical ``*-source-semantics`` reasons are
    preserved only for indeterminate/incomplete family extraction so existing
    consumers still receive the legacy signal where it remains meaningful.
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

    @staticmethod
    def _legacy_marker_required(family: str, rule) -> bool:
        semantics = rule.source_attributes.get("pan_ipv6_nat_semantics") or {}
        semantics_complete = rule.source_attributes.get(
            "pan_ipv6_nat_semantics_complete"
        )

        if semantics_complete is False:
            return True

        if family == "nat64":
            return semantics.get("flow") in {None, "indeterminate"}

        return False

    def _enhance_nat_rule(self, scope: PANScope, entry: ET.Element, extraction, rule) -> None:
        super()._enhance_nat_rule(scope, entry, extraction, rule)

        family = self._compat_nat_family(entry)
        if family not in {"nat64", "nptv6"}:
            return

        legacy_reason = f"{family}-source-semantics"
        legacy_required = self._legacy_marker_required(family, rule)

        if legacy_required:
            if legacy_reason not in rule.review_reasons:
                rule.review_reasons.append(legacy_reason)
        else:
            while legacy_reason in rule.review_reasons:
                rule.review_reasons.remove(legacy_reason)

        rule.review_reasons = list(dict.fromkeys(rule.review_reasons))
        rule.requires_manual_review = bool(rule.review_reasons)
        rule.migration_status = (
            "PARTIALLY_NORMALIZED" if rule.review_reasons else "NORMALIZED"
        )

        item = self._inventory_item(extraction, "nat", scope, entry.get("name"))
        if item is not None:
            item.source_attributes.update(rule.source_attributes)
            item.requires_manual_review = rule.requires_manual_review
            if legacy_required:
                note = f"Compatibility review marker retained: {legacy_reason}."
                if note not in item.notes:
                    item.notes.append(note)
            else:
                item.notes = [
                    note for note in item.notes
                    if legacy_reason not in note
                ]
