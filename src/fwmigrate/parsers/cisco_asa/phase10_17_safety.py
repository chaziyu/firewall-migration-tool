from __future__ import annotations

from typing import Any, List, Optional, Tuple

from fwmigrate.extraction.sanitize import sanitize_raw_text
from fwmigrate.parsers.cisco_asa.model_phase10_17 import CiscoConnectionControlPhase11


def _parse_class_map_header_ci(
    parts: List[str], line_number: int
) -> Tuple[str, Optional[str], Optional[str], Optional[str], bool]:
    lower = [part.lower() for part in parts]
    invalid = f"class-map-invalid-line-{line_number}"
    if len(parts) == 2 and lower[0] == "class-map":
        return parts[1], "layer3_4", None, None, False
    if len(parts) == 3 and lower[0] == "class-map" and lower[1] in {"match-any", "match-all"}:
        return parts[2], "layer3_4", None, lower[1], False
    if len(parts) >= 4 and lower[:2] == ["class-map", "type"]:
        map_type = lower[2]
        if map_type == "inspect":
            if len(parts) == 5:
                return parts[4], "inspect", lower[3], "match-all", False
            if len(parts) == 6 and lower[4] in {"match-all", "match-any"}:
                return parts[5], "inspect", lower[3], lower[4], False
            return invalid, "inspect", lower[3] if len(parts) > 3 else None, None, True
        if map_type == "management":
            return (parts[3], "management", None, None, False) if len(parts) == 4 else (invalid, "management", None, None, True)
        if map_type == "regex":
            if len(parts) == 4:
                return parts[3], "regex", None, None, False
            if len(parts) == 5 and lower[3] in {"match-any", "match-all"}:
                return parts[4], "regex", None, lower[3], False
            return invalid, "regex", None, None, True
        return invalid, map_type, None, None, True
    return invalid, None, None, None, True


def _parse_policy_map_header_ci(
    parts: List[str], line_number: int
) -> Tuple[str, Optional[str], Optional[str], bool]:
    lower = [part.lower() for part in parts]
    if len(parts) == 2 and lower[0] == "policy-map":
        return parts[1], "layer3_4", None, False
    if len(parts) == 5 and lower[:3] == ["policy-map", "type", "inspect"]:
        return parts[4], "inspect", lower[3], False
    return f"policy-map-invalid-line-{line_number}", None, None, True


def _parse_unverified_global_conn(self: Any, line: str, line_number: int) -> CiscoConnectionControlPhase11:
    """Preserve conn-prefixed top-level syntax without inventing MPF semantics.

    Current ASA references document connection limits under `set connection` in
    policy-map class configuration mode. A standalone conn-prefixed line is
    therefore source inventory until a specific ASA command family is verified.
    """
    safe = sanitize_raw_text(line)
    return CiscoConnectionControlPhase11(
        name=f"unverified-global-connection:{line_number}",
        setting=line.split()[0].lower() if line.split() else "connection",
        control_type="unverified_global_connection",
        raw_lines=[safe],
        source_order=line_number,
        source_attributes={
            "raw_command": safe,
            "unmodeled_tokens": line.split()[1:],
        },
        migration_status="UNSUPPORTED",
        requires_manual_review=True,
        review_reasons=[
            "Standalone conn-prefixed syntax is not modeled as a global equivalent of MPF set connection",
        ],
    )


def apply_phase_10_17_safety(parser_cls: Any) -> None:
    """Apply small hardening fixes after the main Phase 10-17 extension."""
    import fwmigrate.parsers.cisco_asa.phase10_17 as phase

    phase._parse_class_map_header = _parse_class_map_header_ci
    phase._parse_policy_map_header = _parse_policy_map_header_ci
    parser_cls._parse_global_conn = _parse_unverified_global_conn
