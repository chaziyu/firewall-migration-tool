"""Vendor-neutral structured migration diagnostics."""

from __future__ import annotations

from typing import Any

from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus
from fwmigrate.ir import IRConfig


_CANONICAL_COLLECTIONS = {
    "interfaces": "interfaces",
    "zones": "zones",
    "addresses": "addresses",
    "address_groups": "address_groups",
    "services": "services",
    "service_groups": "service_groups",
    "schedules": "schedules",
    "schedule_groups": "schedule_groups",
    "security_policies": "security_policies",
    "nat_rules": "nat_rules",
    "routes": "routes",
    "vpn_tunnels": "vpn_tunnels",
    "virtual_ips": "published_services",
    "ip_pools": "nat_pools",
}


def _status_value(status: Any) -> str:
    return getattr(status, "value", str(status))


class MigrationSummary:
    """Build machine-readable migration diagnostics from normalized data."""

    def __init__(
        self,
        ir: IRConfig,
        target_vendor: str | None = None,
        extraction_result: ExtractionResult | None = None,
    ) -> None:
        self.ir = ir
        self.target_vendor = target_vendor or ir.metadata.target_vendor
        self.extraction_result = extraction_result

    def _canonical_counts(self) -> dict[str, int]:
        counts = {
            key: len(getattr(self.ir, field, ()) or ())
            for key, field in _CANONICAL_COLLECTIONS.items()
        }
        counts["policies"] = counts["security_policies"]
        return counts

    def _status_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in ExtractionStatus}
        for item in (self.extraction_result.inventory_items if self.extraction_result else ()):
            status = _status_value(item.status)
            counts[status] = counts.get(status, 0) + 1
        return counts

    def _blocking_reasons(self) -> list[str]:
        reasons = list(self.extraction_result.blocking_reasons) if self.extraction_result else []
        reasons.extend(getattr(self.ir, "generation_blocking_reasons", []) or [])
        return list(dict.fromkeys(reasons))

    def _source_fidelity(self) -> dict[str, Any]:
        extraction = self.extraction_result
        if extraction is None:
            return {
                "source_sections": 0,
                "inventory_items": 0,
                "source_objects": 0,
                "parsed_objects": 0,
                "normalized_objects": 0,
                "section_status_counts": {},
            }

        section_status_counts: dict[str, int] = {}
        source_objects = parsed_objects = normalized_objects = 0
        for section in extraction.source_sections:
            status = _status_value(section.status)
            section_status_counts[status] = section_status_counts.get(status, 0) + 1
            source_objects += section.object_count_source or 0
            parsed_objects += section.object_count_parsed or 0
            normalized_objects += section.object_count_normalized or 0
        return {
            "source_sections": len(extraction.source_sections),
            "inventory_items": len(extraction.inventory_items),
            "source_objects": source_objects,
            "parsed_objects": parsed_objects,
            "normalized_objects": normalized_objects,
            "section_status_counts": section_status_counts,
        }

    def _extraction_safety_counts(self) -> dict[str, int]:
        extraction = self.extraction_result
        inventory = extraction.inventory_items if extraction else ()
        sections = extraction.source_sections if extraction else ()
        counts = self._status_counts()
        counts.update({
            "withheld_canonical_policies": sum(
                not policy.safe_for_target_generation for policy in self.ir.policies
            ),
            "withheld_canonical_nat_rules": sum(
                not rule.safe_for_target_generation for rule in self.ir.nat_rules
            ),
            "incomplete_source_sections": sum(
                _status_value(section.status) != ExtractionStatus.NORMALIZED.value
                for section in sections
            ),
            "unresolved_uids": sum(
                "unresolved" in note.casefold()
                for item in inventory
                for note in item.notes
            ),
            "scope_ambiguity": sum(
                any(
                    marker in note
                    for marker in ("without-selector", "scope-selection-required")
                )
                for section in sections
                for note in [*section.notes]
            ),
        })
        return counts

    def _migration_critical_configuration(self) -> dict[str, Any]:
        """Return common canonical, source-fidelity, and safety counts."""
        status_counts = self._status_counts()
        blockers = self._blocking_reasons()
        extraction = self.extraction_result
        unresolved = sum(
            _status_value(dependency.result).casefold() == "unresolved"
            for dependency in (extraction.dependencies if extraction else ())
        )
        canonical_counts = self._canonical_counts()
        return {
            **canonical_counts,
            "source_fidelity": self._source_fidelity(),
            "unresolved_dependencies": unresolved,
            "blocked_by_unresolved_dependency": unresolved,
            "partial_objects": status_counts.get(ExtractionStatus.PARTIALLY_NORMALIZED.value, 0),
            "source_only_objects": status_counts.get(ExtractionStatus.EXTRACT_ONLY.value, 0),
            "unsupported_objects": status_counts.get(ExtractionStatus.UNSUPPORTED.value, 0),
            "parse_error_objects": status_counts.get(ExtractionStatus.PARSE_ERROR.value, 0),
            "generation_blockers": len(blockers),
            "status_counts": status_counts,
        }

    def generate_json_summary(self) -> dict[str, Any]:
        """Return structured, vendor-neutral migration diagnostics."""
        extraction = self.extraction_result
        blockers = self._blocking_reasons()
        status_counts = self._status_counts()
        manual_review_items = sum(
            bool(item.requires_manual_review)
            for item in (extraction.inventory_items if extraction else ())
        )
        canonical_counts = self._canonical_counts()
        return {
            "hostname": self.ir.metadata.hostname,
            "source_vendor": self.ir.metadata.source_vendor,
            "target_vendor": self.target_vendor,
            "timestamp": self.ir.metadata.migration_timestamp.isoformat(),
            "counts": canonical_counts,
            "canonical_counts": canonical_counts,
            "source_fidelity": self._source_fidelity(),
            "extraction_status_counts": status_counts,
            "extraction_safety": self._extraction_safety_counts(),
            "migration_critical_configuration": self._migration_critical_configuration(),
            "unresolved_dependencies": sum(
                _status_value(dependency.result).casefold() == "unresolved"
                for dependency in (extraction.dependencies if extraction else ())
            ),
            "requires_manual_review": bool(
                getattr(self.ir, "requires_manual_review", False)
                or (extraction and extraction.requires_manual_review)
            ),
            "manual_review_items": manual_review_items,
            "generation_blocking_reasons": blockers,
            "generation_blockers": len(blockers),
        }

    to_dict = generate_json_summary


def generate_json_summary(
    ir: IRConfig,
    *,
    target_vendor: str | None = None,
    extraction_result: ExtractionResult | None = None,
) -> dict[str, Any]:
    """Convenience wrapper for API and reporting consumers."""
    return MigrationSummary(
        ir,
        target_vendor=target_vendor,
        extraction_result=extraction_result,
    ).generate_json_summary()


__all__ = ["MigrationSummary", "generate_json_summary"]
