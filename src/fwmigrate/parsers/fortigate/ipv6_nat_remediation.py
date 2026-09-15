"""Normalize fully represented FortiOS IPv6 NAT source resources."""

from __future__ import annotations

from typing import Any

from fwmigrate.extraction.models import ExtractionStatus


def _source_complete_ipv6_pool(pool: Any) -> bool:
    return bool(
        getattr(pool, "address_family", None) == "ipv6"
        and not getattr(pool, "source_attributes", {})
        and getattr(pool, "start_ip", None) is not None
        and getattr(pool, "end_ip", None) is not None
    )


def install_ipv6_nat_remediation(extractor_module: Any) -> None:
    original = extractor_module.extract_fortigate_config
    if getattr(original, "_ipv6_nat_remediation", False):
        return

    def extract_fortigate_config(text: str, zone_mapping=None):
        result = original(text, zone_mapping=zone_mapping)
        ir = result.canonical_ir
        normalized_names: set[tuple[str, str]] = set()
        for pool in getattr(ir, "ip_pools", []):
            if not _source_complete_ipv6_pool(pool):
                continue
            pool.migration_status = "NORMALIZED"
            pool.requires_manual_review = False
            normalized_names.add((getattr(pool, "source_context", None) or "root", pool.name))

        for item in result.inventory_items:
            if item.source_path != "firewall ippool6" or not item.name:
                continue
            key = (item.source_context or "root", item.name)
            if key in normalized_names:
                item.status = ExtractionStatus.NORMALIZED
                item.requires_manual_review = False

        for section in result.source_sections:
            if section.path != "firewall ippool6":
                continue
            context = section.source_context or "root"
            section_pools = [
                pool for pool in ir.ip_pools
                if getattr(pool, "address_family", None) == "ipv6"
                and (getattr(pool, "source_context", None) or "root") == context
            ]
            if section_pools and all(_source_complete_ipv6_pool(pool) for pool in section_pools):
                section.status = ExtractionStatus.NORMALIZED

        result.requires_manual_review = bool(result.blocking_reasons) or any(
            item.requires_manual_review for item in result.inventory_items
        )
        ir.requires_manual_review = result.requires_manual_review
        return result

    extract_fortigate_config._ipv6_nat_remediation = True
    extractor_module.extract_fortigate_config = extract_fortigate_config


__all__ = ["install_ipv6_nat_remediation"]
