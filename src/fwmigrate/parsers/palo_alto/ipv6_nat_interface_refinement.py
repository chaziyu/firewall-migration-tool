"""Interface-backed refinements for PAN-OS NAT64/NPTv6 semantics."""
from __future__ import annotations

from typing import Any, Dict, List

from fwmigrate.ir.enums import NATTranslationMode

from .source_model import PANScope


class PANOSIPv6NATInterfaceRefinementMixin:
    """Use Phase 2 interface-address evidence for IPv6 NAT family checks."""

    @staticmethod
    def _interface_address_families(details: Any) -> List[str]:
        if not isinstance(details, dict):
            return []
        families: List[str] = []
        validation = details.get("value_validation", {})
        if isinstance(validation, dict):
            for records in validation.values():
                if not isinstance(records, list):
                    continue
                for record in records:
                    if not isinstance(record, dict) or not record.get("valid"):
                        continue
                    family = record.get("address_family")
                    if family in {"ipv4", "ipv6"} and family not in families:
                        families.append(family)
        return families

    def _nat64_semantics(self, scope: PANScope, entry, rule):
        semantics, reasons = super()._nat64_semantics(scope, entry, rule)
        details = rule.source_attributes.get("pan_interface_address_details")
        if not isinstance(details, dict):
            return semantics, reasons

        semantics["interface_address"] = details
        interface_families = self._interface_address_families(details)
        semantics["interface_address_families"] = interface_families

        if semantics.get("flow") == "indeterminate":
            original_families = set(semantics.get("original", {}).get("families", []))
            if original_families == {"ipv6"} and "ipv4" in interface_families:
                semantics["flow"] = "ipv6-initiated"
                semantics.setdefault("translated", {}).setdefault("families", [])
                if "ipv4" not in semantics["translated"]["families"]:
                    semantics["translated"]["families"].append("ipv4")
                rule.original_address_family = "ipv6"
                rule.translated_address_family = "ipv4"
            elif original_families == {"ipv4"} and "ipv6" in interface_families:
                semantics["flow"] = "ipv4-initiated"
                semantics.setdefault("translated", {}).setdefault("families", [])
                if "ipv6" not in semantics["translated"]["families"]:
                    semantics["translated"]["families"].append("ipv6")
                rule.original_address_family = "ipv4"
                rule.translated_address_family = "ipv6"
            elif (
                rule.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
                and original_families
                and not interface_families
            ):
                reasons.append("nat64-interface-address-family-indeterminate")

        if details.get("invalid_values"):
            reasons.append("invalid-nat64-interface-address-value")
        return semantics, list(dict.fromkeys(reasons))

    def _nptv6_semantics(self, scope: PANScope, entry, rule):
        semantics, reasons = super()._nptv6_semantics(scope, entry, rule)
        details = rule.source_attributes.get("pan_interface_address_details")
        if not isinstance(details, dict):
            return semantics, reasons

        semantics["interface_address"] = details
        interface_families = self._interface_address_families(details)
        semantics["interface_address_families"] = interface_families
        if semantics.get("dynamic_interface_prefix"):
            if details.get("invalid_values"):
                reasons.append("invalid-nptv6-interface-prefix-selector")
            if "ipv4" in interface_families:
                reasons.append("nptv6-interface-prefix-must-be-ipv6")
        return semantics, list(dict.fromkeys(reasons))
