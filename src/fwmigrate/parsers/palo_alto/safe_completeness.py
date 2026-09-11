"""Safety-preserving wrapper for PAN-OS completeness extensions.

The completeness layer captures additional source semantics. This wrapper keeps
existing fail-closed IR contracts intact where a populated generic field would
incorrectly imply cross-vendor portability.
"""
from __future__ import annotations

import ipaddress
from typing import Any, List

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.core import IRInterfaceIPv4Address, IRPANSDWANLinkSettings

from .completeness import PANOSSourceParser as _CompletenessPANOSSourceParser
from .source_model import PANScope, pan_scope_identity
from .xml_utils import member_texts


class PANOSSourceParser(_CompletenessPANOSSourceParser):
    """Lossless PAN-OS extraction that preserves established IR safety rules."""

    def _enhance_security_policy(self, scope, entry, extraction, policy) -> None:
        super()._enhance_security_policy(scope, entry, extraction, policy)

        # Policy tags are metadata. A missing local tag definition must not
        # change the rule's migration safety classification; the raw tag name
        # remains preserved and any resolved object name is still recorded.
        if "unresolved-tags" in policy.review_reasons:
            policy.review_reasons.remove("unresolved-tags")
        policy.requires_manual_review = bool(policy.review_reasons)
        policy.migration_status = (
            "PARTIALLY_NORMALIZED" if policy.review_reasons else "NORMALIZED"
        )

        item = self._inventory_item(extraction, "policies", scope, entry.get("name"))
        if item is not None:
            item.status = (
                ExtractionStatus.PARTIALLY_NORMALIZED
                if policy.review_reasons
                else ExtractionStatus.NORMALIZED
            )
            item.requires_manual_review = bool(policy.review_reasons)

    def _enhance_zones(self, scope: PANScope, search_root, extraction, zones: List[Any]) -> None:
        super()._enhance_zones(scope, search_root, extraction, zones)
        # `IRZone.source_context` is consumed as portable target context by
        # existing generators. PAN-OS scope is therefore kept in source
        # attributes instead of populating that generic field.
        for zone in zones:
            zone.source_context = None
            zone.source_attributes["pan_source_context"] = pan_scope_identity(scope)

    def _enhance_profile_groups(self, scope: PANScope, extraction, groups: List[Any]) -> None:
        super()._enhance_profile_groups(scope, extraction, groups)
        # Same safety rule as zones: retain PAN scope explicitly in source
        # evidence without asserting generic cross-vendor target context.
        for group in groups:
            group.source_context = None
            group.source_attributes["pan_source_context"] = pan_scope_identity(scope)

    def _parse_schedules(self, scope: PANScope, search_root, extraction):
        before = len(extraction.canonical_ir.schedules)
        super()._parse_schedules(scope, search_root, extraction)

        # Complex PAN-OS schedules are now represented losslessly in `windows`
        # and `recurrence`, but remain `source-only` so target generators cannot
        # broaden differing windows into a single recurring interval.
        for schedule in extraction.canonical_ir.schedules[before:]:
            source_windows = schedule.source_attributes.get("pan_schedule_windows", {})
            daily = source_windows.get("daily", [])
            weekly = source_windows.get("weekly", {})
            non_recurring = source_windows.get("non_recurring", [])

            complex_schedule = (
                len(daily) > 1
                or any(len(values) > 1 for values in weekly.values())
                or len({
                    (values[0].get("start"), values[0].get("end"))
                    for values in weekly.values()
                    if values
                }) > 1
                or len(non_recurring) > 1
            )
            if complex_schedule:
                schedule.schedule_type = "source-only"
                schedule.requires_manual_review = True
                schedule.migration_status = "PARTIALLY_NORMALIZED"
                if "multiple-or-differing-windows" not in schedule.review_reasons:
                    schedule.review_reasons.append("multiple-or-differing-windows")

                item = self._inventory_item(extraction, "schedules", scope, schedule.name)
                if item is not None:
                    item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                    item.requires_manual_review = True
                    note = (
                        "PAN-OS schedule has multiple or differing windows; "
                        "typed windows are preserved without broadening target semantics."
                    )
                    if note not in item.notes:
                        item.notes.append(note)

    def _enhance_interfaces(self, extraction) -> None:
        super()._enhance_interfaces(extraction)

        # PAN-OS permits multiple addresses directly on one L3 interface.
        # Generic `secondary_ips` has vendor-specific semantics in existing
        # targets, so do not reinterpret those PAN addresses as secondaries.
        for interface in extraction.canonical_ir.interfaces:
            ipv4 = list(interface.source_attributes.get("pan_ipv4_addresses", []))
            interface.additional_ipv4_addresses = []
            for value in ipv4[1:]:
                try:
                    parsed = ipaddress.ip_interface(value)
                except ValueError:
                    continue
                if parsed.version == 4:
                    interface.additional_ipv4_addresses.append(
                        IRInterfaceIPv4Address(address=str(parsed), source_address=value)
                    )
            settings = interface.source_attributes.get("pan_sdwan_link_settings")
            if settings:
                node = settings.get("sdwan-link-settings", settings) if isinstance(settings, dict) else {}
                def scalar(*names):
                    def walk(value):
                        if isinstance(value, dict):
                            for key in names:
                                candidate = value.get(key)
                                if isinstance(candidate, dict) and candidate.get("text"):
                                    return candidate["text"]
                                if isinstance(candidate, str) and candidate:
                                    return candidate
                            for child in value.values():
                                found = walk(child)
                                if found:
                                    return found
                        elif isinstance(value, list):
                            for child in value:
                                found = walk(child)
                                if found:
                                    return found
                        return None
                    return walk(node)
                interface_profile = scalar("sdwan-interface-profile", "interface-profile", "profile")
                path_quality = scalar("path-quality-profile")
                traffic_distribution = scalar("traffic-distribution-profile")
                saas_quality = scalar("saas-quality-profile")
                reasons = []
                checks = (
                    (interface_profile, extraction.canonical_ir.pan_sdwan_interface_profiles),
                    (path_quality, extraction.canonical_ir.pan_sdwan_path_quality_profiles),
                    (traffic_distribution, extraction.canonical_ir.pan_sdwan_traffic_distribution_profiles),
                )
                for reference, profiles in checks:
                    if reference and not any(profile.name == reference for profile in profiles):
                        reasons.append(f"unresolved-{reference}-profile")
                link = IRPANSDWANLinkSettings(
                    interface=interface.name,
                    interface_profile=interface_profile, path_quality_profile=path_quality,
                    traffic_distribution_profile=traffic_distribution,
                    saas_quality_profile=saas_quality, review_reasons=reasons,
                    source_attributes=settings,
                )
                link.requires_manual_review = True
                extraction.canonical_ir.pan_sdwan_link_settings.append(link)
            if len(ipv4) > 1:
                interface.secondary_ips = []
                interface.source_attributes["pan_additional_ipv4_addresses"] = ipv4[1:]
                if "multiple-ipv4-addresses" not in interface.review_reasons:
                    interface.review_reasons.append("multiple-ipv4-addresses")
                interface.requires_manual_review = True
                interface.migration_status = "PARTIALLY_NORMALIZED"

                for item in extraction.inventory_items:
                    if item.domain != "interfaces" or item.name != interface.name:
                        continue
                    item.source_attributes["pan_additional_ipv4_addresses"] = ipv4[1:]
                    item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                    item.requires_manual_review = True
                    note = (
                        "Multiple PAN-OS IPv4 addresses are preserved explicitly "
                        "without mapping them to generic secondary-IP semantics."
                    )
                    if note not in item.notes:
                        item.notes.append(note)
