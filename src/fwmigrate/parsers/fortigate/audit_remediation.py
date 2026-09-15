"""Focused FortiOS 7.4.6 audit remediations.

The active FortiGate parser is intentionally conservative.  This extension
separates source completeness from target portability for source semantics that
are already represented losslessly, while preserving fail-closed behavior for
unknown or malformed input.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    UnsupportedItem,
)


_MULTI_VDOM_BLOCKER = (
    "Multiple FortiGate VDOMs are present; target generation requires an explicit "
    "context-to-target-scope mapping"
)
_GENERIC_CANONICAL_REVIEW_BLOCKER = (
    "One or more traffic-affecting canonical objects require manual review"
)
_KNOWN_IPV4_POOL_TYPES = {
    None,
    "overload",
    "one-to-one",
    "fixed-port-range",
    "port-block-allocation",
    "cgn-resource-allocation",
}
_POOL_PORTABILITY_REASON_MARKERS = (
    "target-specific",
    "full-cone behavior",
    "fixed-port-range pool semantics",
    "port-block-allocation pool semantics",
    "IP pool PBA settings",
    "IP pool source range",
    "IP pool exclusions",
    "cgn-resource-allocation",
)


def _find_unquoted_hash(line: str) -> int | None:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote is not None:
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#":
            return index
    return None


def _unsupported_source_lines(text: str) -> list[tuple[int, str, str]]:
    findings: list[tuple[int, str, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^select(?:\s+|$)", stripped, flags=re.IGNORECASE):
            findings.append((line_number, "select", stripped))
            continue
        hash_index = _find_unquoted_hash(raw_line)
        if hash_index is not None and raw_line[:hash_index].strip():
            findings.append((line_number, "inline-comment", stripped))
    return findings


def _pool_source_complete(pool: Any) -> bool:
    return bool(
        getattr(pool, "address_family", "ipv4") == "ipv4"
        and getattr(pool, "pool_type", None) in _KNOWN_IPV4_POOL_TYPES
        and not getattr(pool, "source_attributes", {})
    )


def _pool_portability_reason(reason: str) -> bool:
    return any(marker.lower() in reason.lower() for marker in _POOL_PORTABILITY_REASON_MARKERS)


def _normalize_complete_pools_and_rules(ir: Any) -> None:
    pools = {
        (getattr(pool, "source_context", None) or "root", pool.name): pool
        for pool in getattr(ir, "ip_pools", [])
    }
    for pool in pools.values():
        if not _pool_source_complete(pool):
            continue
        pool.migration_status = "NORMALIZED"
        pool.requires_manual_review = False

    for rule in getattr(ir, "nat_rules", []):
        refs = list(getattr(rule, "source_pool_references", []) or [])
        if not refs:
            continue
        context = getattr(rule, "source_context", None) or "root"
        resolved = [pools.get((context, name)) for name in refs]
        if not resolved or any(pool is None or not _pool_source_complete(pool) for pool in resolved):
            continue
        reasons = list(getattr(rule, "review_reasons", []) or [])
        if not reasons or not all(_pool_portability_reason(reason) for reason in reasons):
            continue
        rule.review_reasons = []
        rule.requires_manual_review = False
        rule.migration_status = "NORMALIZED"


def _normalize_complete_vip_groups(ir: Any) -> None:
    for group in getattr(ir, "virtual_ip_groups", []):
        if getattr(group, "unresolved_members", []):
            continue
        if getattr(group, "source_attributes", {}):
            continue
        group.migration_status = "NORMALIZED"
        group.requires_manual_review = False
        if getattr(group, "audit_note", None) and "unresolved" not in group.audit_note.lower():
            group.audit_note = None


def _critical_review_objects(ir: Any) -> Iterable[Any]:
    ipv4_pools = [
        pool for pool in getattr(ir, "ip_pools", [])
        if getattr(pool, "address_family", "ipv4") == "ipv4"
    ]
    collections = (
        getattr(ir, "interfaces", []),
        getattr(ir, "policies", []),
        getattr(ir, "multicast_policies", []),
        getattr(ir, "nat_rules", []),
        getattr(ir, "routes", []),
        getattr(ir, "addresses", []),
        getattr(ir, "address_groups", []),
        getattr(ir, "services", []),
        getattr(ir, "service_groups", []),
        ipv4_pools,
        getattr(ir, "virtual_ips", []),
    )
    for collection in collections:
        yield from collection


def _sync_inventory_status(result: Any) -> None:
    ir = result.canonical_ir
    pools = {
        (getattr(pool, "source_context", None) or "root", pool.name): pool
        for pool in getattr(ir, "ip_pools", [])
        if getattr(pool, "address_family", "ipv4") == "ipv4"
    }
    groups = {
        (
            getattr(group, "source_context", None) or "root",
            group.name,
            getattr(group, "address_family", "ipv4"),
        ): group
        for group in getattr(ir, "virtual_ip_groups", [])
    }
    for item in result.inventory_items:
        context = item.source_context or "root"
        if item.source_path == "firewall ippool" and item.name:
            pool = pools.get((context, item.name))
            if pool and pool.migration_status == "NORMALIZED" and not pool.requires_manual_review:
                item.status = ExtractionStatus.NORMALIZED
                item.requires_manual_review = False
        elif item.source_path in {"firewall vipgrp", "firewall vipgrp6"} and item.name:
            family = "ipv6" if item.source_path.endswith("vipgrp6") else "ipv4"
            group = groups.get((context, item.name, family))
            if group and group.migration_status == "NORMALIZED" and not group.requires_manual_review:
                item.status = ExtractionStatus.NORMALIZED
                item.requires_manual_review = False

    for section in result.source_sections:
        if section.path == "firewall ippool":
            section_pools = [
                pool for (context, _), pool in pools.items()
                if context == (section.source_context or "root")
            ]
            if section_pools and all(
                pool.migration_status == "NORMALIZED" and not pool.requires_manual_review
                for pool in section_pools
            ):
                section.status = ExtractionStatus.NORMALIZED
        elif section.path in {"firewall vipgrp", "firewall vipgrp6"}:
            family = "ipv6" if section.path.endswith("vipgrp6") else "ipv4"
            section_groups = [
                group for (context, _, item_family), group in groups.items()
                if context == (section.source_context or "root") and item_family == family
            ]
            if section_groups and all(
                group.migration_status == "NORMALIZED" and not group.requires_manual_review
                for group in section_groups
            ):
                section.status = ExtractionStatus.NORMALIZED


def _remove_resolved_source_only_blockers(result: Any) -> None:
    ir = result.canonical_ir
    blockers = list(result.blocking_reasons)
    if _GENERIC_CANONICAL_REVIEW_BLOCKER in blockers:
        still_unsafe = any(
            getattr(obj, "requires_manual_review", False)
            or getattr(obj, "migration_status", "NORMALIZED") != "NORMALIZED"
            or bool(getattr(obj, "review_reasons", []))
            for obj in _critical_review_objects(ir)
        )
        if not still_unsafe:
            blockers.remove(_GENERIC_CANONICAL_REVIEW_BLOCKER)
    result.blocking_reasons = list(dict.fromkeys(blockers))
    ir.generation_blocking_reasons = list(result.blocking_reasons)
    result.generation_safe = not result.blocking_reasons
    result.migration_complete = not result.blocking_reasons
    ir.generation_safe = result.generation_safe


def _record_unsupported_syntax(result: Any, findings: list[tuple[int, str, str]]) -> None:
    if not findings:
        return
    for line_number, kind, raw in findings:
        if kind == "select":
            parts = raw.split()
            values = parts[1:]
            message = (
                f"Unsupported FortiOS select operation at line {line_number}; "
                "interactive selection semantics are not applied during configuration extraction."
            )
            result.inventory_items.append(
                SourceInventoryItem(
                    domain="unsupported-cli",
                    source_path="unsupported select",
                    commands=[
                        SourceCommand(
                            operation="select",
                            key=values[0] if values else "",
                            values=values[1:] if len(values) > 1 else [],
                            line_number=line_number,
                            status=ExtractionStatus.UNSUPPORTED,
                            requires_manual_review=True,
                        )
                    ],
                    status=ExtractionStatus.UNSUPPORTED,
                    requires_manual_review=True,
                    notes=["unsupported-interactive-operation"],
                )
            )
        else:
            message = (
                f"Unsupported unquoted inline comment syntax at line {line_number}; "
                "the source line is retained for review instead of guessing where the command ends."
            )
        result.unsupported_items.append(
            UnsupportedItem(
                source_path="raw configuration",
                reason=message,
                requires_manual_review=True,
                raw_capture=raw,
            )
        )
        result.blocking_reasons.append(message)
    result.blocking_reasons = list(dict.fromkeys(result.blocking_reasons))
    result.requires_manual_review = True
    result.generation_safe = False
    result.migration_complete = False
    ir = result.canonical_ir
    ir.requires_manual_review = True
    ir.generation_safe = False
    ir.generation_blocking_reasons = list(
        dict.fromkeys([*ir.generation_blocking_reasons, *result.blocking_reasons])
    )


def install_fortios_746_audit_remediation(extractor_module: Any) -> None:
    """Install source-accounting and source-completeness remediation."""
    original = extractor_module.extract_fortigate_config
    if getattr(original, "_fortios_746_audit_remediation", False):
        return

    def extract_fortigate_config(text: str, zone_mapping=None):
        findings = _unsupported_source_lines(text)
        result = original(text, zone_mapping=zone_mapping)
        _normalize_complete_pools_and_rules(result.canonical_ir)
        _normalize_complete_vip_groups(result.canonical_ir)
        _sync_inventory_status(result)
        _remove_resolved_source_only_blockers(result)
        _record_unsupported_syntax(result, findings)
        result.requires_manual_review = bool(result.blocking_reasons) or any(
            item.requires_manual_review for item in result.inventory_items
        )
        result.canonical_ir.requires_manual_review = result.requires_manual_review
        return result

    extract_fortigate_config._fortios_746_audit_remediation = True
    extractor_module.extract_fortigate_config = extract_fortigate_config


__all__ = [
    "install_fortios_746_audit_remediation",
    "_MULTI_VDOM_BLOCKER",
]
