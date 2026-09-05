"""Extract persistent SecureXL/CoreXL settings and operational evidence."""

from __future__ import annotations

import shlex
from collections import defaultdict
from typing import List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
from fwmigrate.ir.core import (
    IRCheckpointCoreXLSettings,
    IRCheckpointPerformanceSettings,
    IRCheckpointSecureXLSettings,
)


_SECUREXL_STATES = {"on": True, "enable": True, "enabled": True, "off": False, "disable": False, "disabled": False}
_OPERATIONAL_COMMANDS = {
    ("fwaccel", "stat"), ("fwaccel", "stats"), ("fwaccel", "conns"),
    ("fwaccel", "templates"), ("fwaccel", "dos"),
    ("fw", "ctl", "multik", "stat"), ("fw", "ctl", "multik", "print"),
    ("fw", "ctl", "multik", "utilization"), ("cpview",), ("top",), ("sar",),
}


def _tokens(line: str) -> Optional[List[str]]:
    try:
        return [token.lower() for token in shlex.split(line)]
    except ValueError:
        return None


def _is_securexl_persistent_command(tokens: Optional[List[str]]) -> bool:
    return bool(tokens and ((tokens[:2] == ["set", "securexl"] and len(tokens) >= 3)
                            or (tokens[:2] == ["set", "fwaccel"] and len(tokens) == 3)))


def _is_corexl_persistent_command(tokens: Optional[List[str]]) -> bool:
    return bool(tokens and tokens[:2] == ["set", "corexl"] and len(tokens) >= 3)


def _is_performance_operational_command(tokens: Optional[List[str]]) -> bool:
    return bool(tokens and (tuple(tokens) in _OPERATIONAL_COMMANDS or tokens[:1] in [["fwaccel"], ["cpview"], ["top"], ["sar"]]))


def _is_performance_family_command(tokens: Optional[List[str]]) -> bool:
    return bool(tokens and (tokens[:2] in [["set", "securexl"], ["set", "corexl"]]
                            or tokens[:1] == ["fwaccel"] or tokens[:3] == ["fw", "ctl", "multik"]
                            or tokens[:1] in [["cpview"], ["top"], ["sar"]]))


def is_performance_command(line: str) -> bool:
    """Keep performance-family commands out of generic Gaia inventory."""
    tokens = _tokens(line)
    return _is_securexl_persistent_command(tokens) or _is_corexl_persistent_command(tokens) or _is_performance_family_command(tokens)


def _inventory(line: str, context: str, source_type: str, status: ExtractionStatus,
               notes: List[str], attributes: dict) -> SourceInventoryItem:
    return SourceInventoryItem(
        domain="gaia", source_path="gaia/show-configuration/performance",
        name=f"{source_type}-{context}", source_type=source_type, source_context=context,
        source_attributes=sanitize_source_attributes(attributes), status=status,
        requires_manual_review=status != ExtractionStatus.NORMALIZED, notes=notes,
    )


def extract_performance_settings(
    text: str, *, domain: Optional[str] = None, gateway: Optional[str] = None,
    source_response: Optional[str] = None, cluster_member: Optional[str] = None,
) -> Tuple[List[IRCheckpointPerformanceSettings], List[SourceInventoryItem]]:
    settings: List[IRCheckpointPerformanceSettings] = []
    inventory: List[SourceInventoryItem] = []
    context = ":".join(str(value or "unknown") for value in (domain, gateway, cluster_member, source_response))
    by_feature = defaultdict(list)
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        tokens = _tokens(line)
        if _is_securexl_persistent_command(tokens):
            tail = tokens[2:]
            state_token = tail[-1] if tail and tail[-1] in _SECUREXL_STATES else None
            valid = (tokens[:2] == ["set", "fwaccel"] and len(tokens) == 3 and state_token is not None) or (
                tokens[:2] == ["set", "securexl"] and len(tail) == 2 and tail[0] == "state" and state_token is not None
            )
            status = ExtractionStatus.NORMALIZED if valid else ExtractionStatus.PARSE_ERROR
            attrs = {"raw_command": sanitize_raw_text(line), "gateway": gateway, "cluster_member": cluster_member}
            item = IRCheckpointSecureXLSettings(name=f"securexl_{line_number}", source_command=sanitize_raw_text(line), source_context=context,
                enabled=_SECUREXL_STATES.get(state_token) if valid else None, settings=attrs, source_attributes=attrs,
                migration_status=status.value, requires_manual_review=status != ExtractionStatus.NORMALIZED)
            settings.append(item); by_feature["securexl"].append((item, line_number))
            inventory.append(_inventory(line, context, "checkpoint-securexl", status, [] if valid else ["malformed-securexl-persistent-setting"], attrs))
            continue
        if _is_corexl_persistent_command(tokens):
            tail = tokens[2:]
            enabled = next((_SECUREXL_STATES[token] for token in tail if token in _SECUREXL_STATES), None)
            count_raw = next((tail[i + 1] for i, token in enumerate(tail[:-1]) if token in {"instances", "instance-count"}), None)
            count_requested = any(token in {"instances", "instance-count"} for token in tail)
            valid = (not count_requested or count_raw is not None and count_raw.isdigit())
            status = ExtractionStatus.NORMALIZED if valid else ExtractionStatus.PARSE_ERROR
            count = int(count_raw) if valid and count_raw is not None else None
            attrs = {"raw_command": sanitize_raw_text(line), "gateway": gateway, "cluster_member": cluster_member}
            item = IRCheckpointCoreXLSettings(name=f"corexl_{line_number}", source_command=sanitize_raw_text(line), source_context=context,
                enabled=enabled, instance_count=count, instance_count_explicit=count_raw is not None,
                settings=attrs, source_attributes=attrs, migration_status=status.value,
                requires_manual_review=status != ExtractionStatus.NORMALIZED)
            settings.append(item); by_feature["corexl"].append((item, line_number))
            inventory.append(_inventory(line, context, "checkpoint-corexl", status, [] if valid else ["invalid-corexl-instance-count"], attrs))
            continue
        if _is_performance_family_command(tokens):
            attrs = {"raw_command": sanitize_raw_text(line), "gateway": gateway, "cluster_member": cluster_member}
            if _is_performance_operational_command(tokens):
                notes = ["runtime-operational-evidence"]
                if len(tokens) > 1 and tuple(tokens) not in _OPERATIONAL_COMMANDS:
                    notes.append("unrecognized-performance-command")
            else:
                notes = ["unrecognized-performance-command"]
            source_type = "checkpoint-performance-operational"
            if tokens[:1] == ["fwaccel"]: source_type = "checkpoint-securexl-operational"
            elif tokens[:3] == ["fw", "ctl", "multik"]: source_type = "checkpoint-corexl-operational"
            inventory.append(_inventory(line, context, source_type, ExtractionStatus.EXTRACT_ONLY, notes, attrs))
    for feature, entries in by_feature.items():
        states = {item.enabled for item, _ in entries if item.enabled is not None}
        counts = {item.instance_count for item, _ in entries if item.instance_count is not None}
        if len(states) > 1 or len(counts) > 1:
            for item, _ in entries:
                item.migration_status = ExtractionStatus.PARTIALLY_NORMALIZED.value
                item.requires_manual_review = True
            for item in inventory:
                if item.source_type == f"checkpoint-{feature}":
                    item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                    item.requires_manual_review = True
                    item.notes.append(f"conflicting-{feature}-{'enable' if feature == 'securexl' else 'instance-count'}")
    return settings, inventory
