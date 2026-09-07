"""Typed source-oriented coverage for PAN-OS NAT interface-address semantics."""
from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import NATTranslationMode

from .source_model import PANScope
from .xml_utils import structured_xml_capture, text_or_none


_INTERFACE_ADDRESS_FIELDS = ("interface", "ip", "ipv6", "floating-ip")


class PANOSNATInterfaceAddressCoverageMixin:
    """Complete PAN-OS source-NAT interface-address extraction without guessing.

    The canonical NAT mode already has an INTERFACE_ADDRESS value, but the PAN-OS
    parser historically kept IPv6 and floating-IP selectors only in raw source
    evidence.  This mixin promotes all documented interface-address children
    into a structured, source-oriented audit record while keeping their exact
    source values and context-dependent reference state.
    """

    @staticmethod
    def _interface_address_values(node: ET.Element, field: str) -> List[str]:
        values: List[str] = []
        for field_node in node.findall(f"./{field}"):
            members = [
                (member.text or "").strip()
                for member in field_node.findall("./member")
                if (member.text or "").strip()
            ]
            if members:
                values.extend(members)
                continue

            entries = [
                (entry.get("name") or "").strip()
                for entry in field_node.findall("./entry")
                if (entry.get("name") or "").strip()
            ]
            if entries:
                values.extend(entries)
                continue

            scalar = (field_node.text or "").strip()
            if scalar:
                values.append(scalar)
        return values

    @staticmethod
    def _validate_interface_address_values(
        values: List[str],
        expected_family: Optional[int],
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for value in values:
            record: Dict[str, Any] = {"value": value}
            try:
                try:
                    parsed = ipaddress.ip_interface(value)
                except ValueError:
                    parsed = ipaddress.ip_address(value)
                family = parsed.version
                record["address_family"] = f"ipv{family}"
                record["valid"] = expected_family is None or family == expected_family
                if expected_family is not None and family != expected_family:
                    record["reason"] = (
                        f"expected ipv{expected_family} value, found ipv{family}"
                    )
            except ValueError as error:
                record["valid"] = False
                record["reason"] = str(error)
            results.append(record)
        return results

    def _parse_complete_interface_address(
        self,
        scope: PANScope,
        node: ET.Element,
    ) -> Dict[str, Any]:
        interface_values = self._interface_address_values(node, "interface")
        ipv4_values = self._interface_address_values(node, "ip")
        ipv6_values = self._interface_address_values(node, "ipv6")
        floating_values = self._interface_address_values(node, "floating-ip")

        details: Dict[str, Any] = {
            "interface": interface_values[0] if len(interface_values) == 1 else None,
            "interfaces": interface_values,
            # Keep the old key for compatibility with existing completeness tests.
            "ip": ipv4_values,
            "ipv4_addresses": ipv4_values,
            "ipv6_addresses": ipv6_values,
            "floating_ips": floating_values,
            "value_validation": {
                "ipv4_addresses": self._validate_interface_address_values(
                    ipv4_values, 4
                ),
                "ipv6_addresses": self._validate_interface_address_values(
                    ipv6_values, 6
                ),
                # Floating-IP is kept family-neutral in the source model. PAN-OS
                # versions differ in where the selector is exposed, so preserve
                # the exact value and report whichever IP family it validates as.
                "floating_ips": self._validate_interface_address_values(
                    floating_values, None
                ),
            },
            "source_entry": structured_xml_capture(node),
        }

        unknown: Dict[str, Any] = {}
        for child in node:
            if child.tag not in _INTERFACE_ADDRESS_FIELDS:
                unknown.setdefault(child.tag, []).append(structured_xml_capture(child))
        if unknown:
            details["unknown_fields"] = unknown

        if len(interface_values) > 1:
            details["interface_cardinality"] = "multiple"
        elif not interface_values:
            details["interface_cardinality"] = "absent"
        else:
            resolved, status = self._resolve_interface_reference(
                scope, interface_values[0]
            )
            details["resolution"] = status
            if resolved is not None:
                details["resolved_interface"] = (
                    resolved.canonical_name or interface_values[0]
                )

        invalid = [
            result
            for results in details["value_validation"].values()
            for result in results
            if not result.get("valid")
        ]
        if invalid:
            details["invalid_values"] = invalid

        return {
            key: value
            for key, value in details.items()
            if value not in (None, [], {})
        }

    @staticmethod
    def _remove_review_reason(rule, reason: str) -> None:
        while reason in rule.review_reasons:
            rule.review_reasons.remove(reason)

    def _interface_address_review_reasons(
        self,
        details: Dict[str, Any],
        *,
        fallback: bool,
    ) -> List[str]:
        reasons: List[str] = []
        if details.get("interface_cardinality") == "multiple":
            reasons.append("multiple-interface-address-interfaces")
        if details.get("unknown_fields"):
            reasons.append("unknown-interface-address-fields")
        if details.get("invalid_values"):
            reasons.append("invalid-interface-address-value")
        if details.get("resolution") == "unresolved":
            reasons.append("unresolved-interface-address-interface")
        if fallback:
            # Fallback semantics are fully extracted, but there is no portable IR
            # field that guarantees target-equivalent exhaustion behavior.
            reasons.append("source-translation-fallback")
        return reasons

    def _enhance_nat_rule(self, scope: PANScope, entry: ET.Element, extraction, rule) -> None:
        super()._enhance_nat_rule(scope, entry, extraction, rule)

        snat = entry.find("./source-translation")
        if snat is None or len(list(snat)) != 1:
            return
        source_node = list(snat)[0]
        attrs = rule.source_attributes

        primary_nodes = source_node.findall("./interface-address")
        if primary_nodes:
            primary_details = [
                self._parse_complete_interface_address(scope, node)
                for node in primary_nodes
            ]
            attrs["pan_interface_address_details_all"] = primary_details
            attrs["pan_interface_address_details"] = (
                primary_details[0] if len(primary_details) == 1 else primary_details
            )

            # A configured primary interface-address is authoritative for the
            # source translation mode, including persistent DIPP.
            rule.source_translation_mode = NATTranslationMode.INTERFACE_ADDRESS

            if len(primary_nodes) == 1:
                primary_reasons = self._interface_address_review_reasons(
                    primary_details[0], fallback=False
                )
                if not primary_reasons:
                    self._remove_review_reason(rule, "interface-address-semantics")
                for reason in primary_reasons:
                    if reason not in rule.review_reasons:
                        rule.review_reasons.append(reason)
            else:
                if "multiple-interface-address-branches" not in rule.review_reasons:
                    rule.review_reasons.append("multiple-interface-address-branches")

        fallback = source_node.find("./fallback")
        if fallback is not None:
            fallback_nodes = fallback.findall(".//interface-address")
            if fallback_nodes:
                fallback_details = [
                    self._parse_complete_interface_address(scope, node)
                    for node in fallback_nodes
                ]
                existing = attrs.get("pan_source_translation_fallback_details")
                if not isinstance(existing, dict):
                    existing = {
                        "source_entry": structured_xml_capture(fallback),
                        "branches": [child.tag for child in fallback],
                    }
                existing["interface_addresses"] = fallback_details
                existing["interface_address"] = (
                    fallback_details[0]
                    if len(fallback_details) == 1
                    else fallback_details
                )
                attrs["pan_source_translation_fallback_details"] = existing

                for details in fallback_details:
                    for reason in self._interface_address_review_reasons(
                        details, fallback=True
                    ):
                        if reason not in rule.review_reasons:
                            rule.review_reasons.append(reason)
                if len(fallback_nodes) > 1:
                    if "multiple-fallback-interface-address-branches" not in rule.review_reasons:
                        rule.review_reasons.append(
                            "multiple-fallback-interface-address-branches"
                        )

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
