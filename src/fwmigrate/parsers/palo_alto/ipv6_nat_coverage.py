"""Source-oriented PAN-OS NAT64 and NPTv6 semantic validation.

This layer keeps NAT address-family semantics independent from NAT direction.
It enriches already-parsed NAT rules with family-specific evidence and
validation without pretending IPv6 NAT is automatically portable to every
target vendor.
"""
from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import NATFamily, NATTranslationMode

from .source_model import PANScope
from .xml_utils import member_texts, structured_xml_capture, text_or_none


class PANOSIPv6NATSemanticsCoverageMixin:
    """Complete source-oriented NAT64/NPTv6 family semantics."""

    @staticmethod
    def _nat_family_value(entry: ET.Element) -> Optional[str]:
        node = entry.find("./nat-type")
        value = text_or_none(entry, "./nat-type")
        if value:
            return value.strip().lower()
        if node is not None and len(node) == 1:
            return next(iter(node)).tag.strip().lower()
        return None

    @staticmethod
    def _translation_values(node: Optional[ET.Element]) -> List[str]:
        if node is None:
            return []
        values = member_texts(node, "./translated-address/member")
        if values:
            return values
        scalar = text_or_none(node, "./translated-address")
        return [scalar] if scalar else []

    @staticmethod
    def _literal_address_family(value: str) -> Optional[int]:
        raw = (value or "").strip()
        if not raw or raw.lower() == "any":
            return None
        try:
            return ipaddress.ip_interface(raw).version
        except ValueError:
            pass
        try:
            return ipaddress.ip_address(raw).version
        except ValueError:
            return None

    def _resolved_selector_values(self, value: str, scope: PANScope) -> List[str]:
        """Return literal network/address values available from an address ref.

        Unresolved, grouped, FQDN, dynamic, and otherwise non-literal objects
        intentionally return an empty list so validation remains indeterminate
        rather than guessing a family.
        """
        direct_family = self._literal_address_family(value)
        if direct_family is not None:
            return [value]
        if value.lower() == "any":
            return []
        resolved = self.resolver.resolve(value, "address-reference", scope)
        if resolved is None or resolved.ir_object is None:
            return []
        obj = resolved.ir_object
        candidates: List[str] = []
        for field in (
            "subnet",
            "ip_range_start",
            "ip_range_end",
            "wildcard_mask",
        ):
            candidate = getattr(obj, field, None)
            if isinstance(candidate, str) and candidate.strip():
                candidates.append(candidate.strip())
        return candidates

    def _selector_family_summary(
        self,
        values: Iterable[str],
        scope: PANScope,
    ) -> Dict[str, Any]:
        known: List[Dict[str, Any]] = []
        indeterminate: List[str] = []
        for value in values:
            raw = (value or "").strip()
            if not raw or raw.lower() == "any":
                continue
            resolved_values = self._resolved_selector_values(raw, scope)
            if not resolved_values:
                indeterminate.append(raw)
                continue
            families = {
                family
                for candidate in resolved_values
                for family in [self._literal_address_family(candidate)]
                if family is not None
            }
            if len(families) == 1:
                known.append({
                    "value": raw,
                    "address_family": f"ipv{next(iter(families))}",
                })
            else:
                indeterminate.append(raw)
        family_set = {
            item["address_family"]
            for item in known
            if item.get("address_family")
        }
        return {
            "known": known,
            "indeterminate": indeterminate,
            "families": sorted(family_set),
        }

    @staticmethod
    def _nptv6_prefix_validation(value: str) -> Dict[str, Any]:
        record: Dict[str, Any] = {"value": value}
        raw = (value or "").strip()
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as error:
            record.update({"valid": False, "reason": str(error)})
            return record
        if network.version != 6:
            record.update({"valid": False, "reason": "NPTv6 requires IPv6 prefixes"})
            return record
        if not 32 <= network.prefixlen <= 112:
            record.update({
                "valid": False,
                "reason": "NPTv6 prefix length must be between /32 and /112",
            })
            return record
        record.update({
            "valid": True,
            "address_family": "ipv6",
            "prefix_length": network.prefixlen,
            "network": str(network),
        })
        return record

    def _nptv6_selector_validation(
        self,
        values: Iterable[str],
        scope: PANScope,
        *,
        allow_any: bool,
    ) -> Dict[str, Any]:
        records: List[Dict[str, Any]] = []
        indeterminate: List[str] = []
        for value in values:
            raw = (value or "").strip()
            if raw.lower() == "any":
                records.append({"value": raw, "valid": allow_any, "builtin": True})
                continue
            resolved_values = self._resolved_selector_values(raw, scope)
            if not resolved_values:
                indeterminate.append(raw)
                continue
            # Address ranges, wildcard masks, FQDNs, and other objects do not
            # become valid NPTv6 prefixes merely because they resolve.
            candidate_records = [
                self._nptv6_prefix_validation(candidate)
                for candidate in resolved_values
            ]
            records.extend(candidate_records)
        return {"records": records, "indeterminate": indeterminate}

    @staticmethod
    def _has_invalid_records(validation: Dict[str, Any]) -> bool:
        return any(
            record.get("valid") is False
            for record in validation.get("records", [])
        )

    @staticmethod
    def _remove_reason(rule, reason: str) -> None:
        while reason in rule.review_reasons:
            rule.review_reasons.remove(reason)

    def _nat64_semantics(
        self,
        scope: PANScope,
        entry: ET.Element,
        rule,
    ) -> tuple[Dict[str, Any], List[str]]:
        source_match = member_texts(entry, "./source/member")
        destination_match = member_texts(entry, "./destination/member")
        source_node = entry.find("./source-translation")
        source_branch = list(source_node)[0] if source_node is not None and len(list(source_node)) == 1 else None
        translated_source = self._translation_values(source_branch)
        destination_node = entry.find("./dynamic-destination-translation")
        if destination_node is None:
            destination_node = entry.find("./destination-translation")
        translated_destination = self._translation_values(destination_node)

        original_summary = self._selector_family_summary(
            [*source_match, *destination_match], scope
        )
        translated_summary = self._selector_family_summary(
            [*translated_source, *translated_destination], scope
        )
        original_families = set(original_summary["families"])
        translated_families = set(translated_summary["families"])

        flow = "indeterminate"
        reasons: List[str] = []
        if original_families == {"ipv6"} and "ipv4" in translated_families:
            flow = "ipv6-initiated"
            rule.original_address_family = "ipv6"
            rule.translated_address_family = "ipv4"
        elif original_families == {"ipv4"} and "ipv6" in translated_families:
            flow = "ipv4-initiated"
            rule.original_address_family = "ipv4"
            rule.translated_address_family = "ipv6"
        elif original_families and translated_families:
            reasons.append("nat64-address-family-mismatch")

        semantics = {
            "family": "nat64",
            "direction": rule.type.value,
            "flow": flow,
            "original": original_summary,
            "translated": translated_summary,
            "source_translation_mode": (
                rule.source_translation_mode.value
                if rule.source_translation_mode is not None
                else None
            ),
            "destination_translation_mode": (
                rule.destination_translation_mode.value
                if rule.destination_translation_mode is not None
                else None
            ),
            "source_entry": structured_xml_capture(entry),
        }
        return semantics, reasons

    def _nptv6_semantics(
        self,
        scope: PANScope,
        entry: ET.Element,
        rule,
    ) -> tuple[Dict[str, Any], List[str]]:
        source_match = member_texts(entry, "./source/member")
        destination_match = member_texts(entry, "./destination/member")
        source_node = entry.find("./source-translation")
        source_branch = list(source_node)[0] if source_node is not None and len(list(source_node)) == 1 else None
        translated_source = self._translation_values(source_branch)
        destination_node = entry.find("./destination-translation")
        if destination_node is None:
            destination_node = entry.find("./dynamic-destination-translation")
        translated_destination = self._translation_values(destination_node)
        translated_port = text_or_none(destination_node, "./translated-port") if destination_node is not None else None

        source_validation = self._nptv6_selector_validation(
            source_match, scope, allow_any=True
        )
        destination_validation = self._nptv6_selector_validation(
            destination_match, scope, allow_any=True
        )
        translated_source_validation = self._nptv6_selector_validation(
            translated_source, scope, allow_any=False
        )
        translated_destination_validation = self._nptv6_selector_validation(
            translated_destination, scope, allow_any=False
        )

        reasons: List[str] = []
        if self._has_invalid_records(source_validation):
            reasons.append("invalid-nptv6-source-prefix")
        if self._has_invalid_records(destination_validation):
            reasons.append("invalid-nptv6-destination-prefix")
        if self._has_invalid_records(translated_source_validation):
            reasons.append("invalid-nptv6-translated-source-prefix")
        if self._has_invalid_records(translated_destination_validation):
            reasons.append("invalid-nptv6-translated-destination-prefix")
        if (
            source_match == ["any"]
            and destination_match == ["any"]
        ):
            reasons.append("nptv6-source-and-destination-both-any")
        if translated_port is not None:
            reasons.append("nptv6-port-translation-not-supported")
        if destination_node is not None and rule.destination_translation_mode not in {
            None,
            NATTranslationMode.STATIC,
        }:
            reasons.append("nptv6-destination-must-be-static")
        if source_branch is not None and source_branch.tag not in {"static-ip", "dynamic-ip"}:
            reasons.append("nptv6-unsupported-source-translation-mode")

        # NPTv6 is IPv6-to-IPv6 prefix translation.  Keep NAT direction
        # independent from family and set the family axis explicitly.
        rule.original_address_family = "ipv6"
        rule.translated_address_family = "ipv6"

        semantics = {
            "family": "nptv6",
            "direction": rule.type.value,
            "original_address_family": "ipv6",
            "translated_address_family": "ipv6",
            "source": source_validation,
            "destination": destination_validation,
            "translated_source": translated_source_validation,
            "translated_destination": translated_destination_validation,
            "translated_port": translated_port,
            "source_translation_mode": (
                rule.source_translation_mode.value
                if rule.source_translation_mode is not None
                else None
            ),
            "destination_translation_mode": (
                rule.destination_translation_mode.value
                if rule.destination_translation_mode is not None
                else None
            ),
            "dynamic_interface_prefix": bool(
                source_branch is not None
                and source_branch.tag == "dynamic-ip"
                and source_branch.find("./interface-address") is not None
            ),
            "source_entry": structured_xml_capture(entry),
        }
        return semantics, reasons

    def _enhance_nat_rule(self, scope: PANScope, entry: ET.Element, extraction, rule) -> None:
        super()._enhance_nat_rule(scope, entry, extraction, rule)

        family = self._nat_family_value(entry)
        if family not in {"nat64", "nptv6"}:
            return

        if family == "nat64":
            rule.nat_family = NATFamily.NAT64
            semantics, validation_reasons = self._nat64_semantics(scope, entry, rule)
        else:
            rule.nat_family = NATFamily.NAT66
            semantics, validation_reasons = self._nptv6_semantics(scope, entry, rule)

        attrs = rule.source_attributes
        attrs["pan_ipv6_nat_semantics"] = semantics
        attrs["pan_ipv6_nat_semantics_complete"] = not validation_reasons
        if validation_reasons:
            attrs["pan_ipv6_nat_validation_reasons"] = validation_reasons
        else:
            attrs.pop("pan_ipv6_nat_validation_reasons", None)

        # Replace the old parser-gap marker with explicit target-portability
        # review.  A rule can now be fully parsed while still being unsafe to
        # emit to a target that lacks equivalent IPv6 NAT behavior.
        self._remove_reason(rule, f"{family}-source-semantics")
        for reason in validation_reasons:
            if reason not in rule.review_reasons:
                rule.review_reasons.append(reason)
        if "source-specific-ipv6-nat-target-semantics" not in rule.review_reasons:
            rule.review_reasons.append("source-specific-ipv6-nat-target-semantics")

        rule.review_reasons = list(dict.fromkeys(rule.review_reasons))
        rule.requires_manual_review = bool(rule.review_reasons)
        rule.migration_status = (
            "PARTIALLY_NORMALIZED" if rule.review_reasons else "NORMALIZED"
        )

        item = self._inventory_item(extraction, "nat", scope, entry.get("name"))
        if item is not None:
            item.source_attributes.update(attrs)
            item.status = (
                ExtractionStatus.PARTIALLY_NORMALIZED
                if rule.review_reasons
                else ExtractionStatus.NORMALIZED
            )
            item.requires_manual_review = bool(rule.review_reasons)
            item.notes = [
                note
                for note in item.notes
                if f"{family}-source-semantics" not in note
            ]
            note = (
                f"PAN-OS {family.upper()} semantics are fully extracted as an "
                "address-family dimension; target portability remains source-specific."
                if not validation_reasons
                else f"PAN-OS {family.upper()} semantics were extracted with validation findings: "
                     f"{', '.join(validation_reasons)}."
            )
            if note not in item.notes:
                item.notes.append(note)
