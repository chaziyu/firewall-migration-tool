"""Extract SecureXL/CoreXL evidence without treating synthetic commands as persistent state."""

from __future__ import annotations

import shlex
from typing import List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
from fwmigrate.ir.core import IRCheckpointPerformanceSettings


_OPERATIONAL_COMMANDS = {
    ("fwaccel", "on"), ("fwaccel", "off"),
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
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        tokens = _tokens(line)
        if _is_securexl_persistent_command(tokens):
            attrs = {"raw_command": sanitize_raw_text(line), "gateway": gateway, "cluster_member": cluster_member}
            inventory.append(_inventory(
                line, context, "checkpoint-securexl", ExtractionStatus.EXTRACT_ONLY,
                ["unsupported-synthetic-securexl-command", "persistent-state-not-proven"], attrs,
            ))
            continue
        if _is_corexl_persistent_command(tokens):
            attrs = {"raw_command": sanitize_raw_text(line), "gateway": gateway, "cluster_member": cluster_member}
            inventory.append(_inventory(
                line, context, "checkpoint-corexl", ExtractionStatus.EXTRACT_ONLY,
                ["unsupported-synthetic-corexl-command", "persistent-state-not-proven"], attrs,
            ))
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
    return settings, inventory
