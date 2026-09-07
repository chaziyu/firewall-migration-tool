from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

from fwmigrate.extraction.sanitize import sanitize_raw_text
from fwmigrate.parsers.cisco_asa.model import CiscoManagementSetting
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
    """Preserve conn-prefixed top-level syntax without inventing MPF semantics."""
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


def _wrap_class_map_block(original: Any):
    """Promote syntactically incomplete match statements to PARSE_ERROR.

    A recognized match family with a missing operand is malformed, not merely an
    unsupported match. This also makes the child diagnostic propagate to Phase
    17 extraction status.
    """
    def parse(self: Any, lines: List[str], index: int):
        record = original(self, lines, index)
        import fwmigrate.parsers.cisco_asa.phase10_17 as phase

        for line_number, _, child, _ in phase._raw_child_rows(lines, index):
            if re.fullmatch(r"match(?:\s+(?:access-list|protocol|port|class-map))?\s*", child, re.I):
                reason = "Malformed class-map match syntax"
                if record.migration_status != "PARSE_ERROR":
                    self._mpf_parse_error(record, line_number, child, "class-map", reason)
                elif not any(
                    diagnostic.line_number == line_number and diagnostic.section == "class-map"
                    for diagnostic in self.config.diagnostics
                ):
                    self._record_diagnostic(line_number, child, reason, "class-map", record.name)
        return record

    return parse


def _wrap_threat_detection(original: Any):
    """Retain the established `threat-detection rate` typed fields."""
    def parse(self: Any, line: str, line_number: int):
        parts = line.split()
        negated = parts[:1] == ["no"]
        effective = parts[1:] if negated else parts
        if len(effective) < 2 or [part.lower() for part in effective[:2]] != ["threat-detection", "rate"]:
            return original(self, line, line_number)

        safe = sanitize_raw_text(line)
        item = CiscoConnectionControlPhase11(
            name=f"threat-detection:{line_number}",
            setting="threat-detection",
            control_type="threat_detection",
            threat_detection_type="rate",
            enabled=not negated,
            negated=negated,
            source_order=line_number,
            raw_lines=[safe],
            values=effective[2:],
            raw_parameters=effective[2:],
            source_attributes={"raw_command": safe, "negated": negated},
            migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=False,
        )
        values = effective[2:]
        position = 0
        fields = {"average-rate", "burst-rate", "interval"}
        while position < len(values):
            key = values[position].lower()
            if key not in fields or position + 1 >= len(values):
                item.requires_manual_review = True
                item.review_reasons.append("Unsupported threat-detection rate parameter")
                break
            value = values[position + 1]
            if not value.isdigit():
                item.migration_status = "PARSE_ERROR"
                item.requires_manual_review = True
                item.review_reasons.append(f"Threat-detection {key} must be numeric")
                self._record_diagnostic(line_number, line, f"Malformed threat-detection {key}", "threat-detection")
                break
            number = int(value)
            if key == "average-rate":
                item.average_rate = number
                item.rate = number
            elif key == "burst-rate":
                item.burst_rate = number
                item.burst = number
            else:
                item.source_attributes["interval"] = number
            position += 2
        return item

    return parse


def _wrap_management(original: Any):
    """Keep typed HTTP server state and the legacy management inventory view."""
    def parse(self: Any, line: str, line_number: int) -> None:
        effective = line[3:].strip() if line.lower().startswith("no ") else line
        is_http_server = effective.lower().startswith("http server ")
        original(self, line, line_number)
        if not is_http_server:
            return

        enabled = None
        parts = effective.split()
        if len(parts) >= 3 and parts[:3] == ["http", "server", "enable"]:
            enabled = not line.lower().startswith("no ")
        if not any(
            item.setting == "http server"
            and item.source_attributes.get("source_line_number") == line_number
            for item in self.config.management_settings
        ):
            self.config.management_settings.append(CiscoManagementSetting(
                name=f"http-server:{line_number}",
                setting="http server",
                enabled=enabled,
                raw_lines=[sanitize_raw_text(line)],
                source_attributes={
                    "raw_command": sanitize_raw_text(line),
                    "source_line_number": line_number,
                },
            ))

    return parse


def apply_phase_10_17_safety(parser_cls: Any) -> None:
    """Apply hardening and compatibility fixes after the main Phase 10-17 extension."""
    import fwmigrate.parsers.cisco_asa.phase10_17 as phase

    phase._parse_class_map_header = _parse_class_map_header_ci
    phase._parse_policy_map_header = _parse_policy_map_header_ci

    parser_cls._parse_class_map_block = _wrap_class_map_block(parser_cls._parse_class_map_block)
    parser_cls._parse_threat_detection = _wrap_threat_detection(parser_cls._parse_threat_detection)
    parser_cls._parse_management_command = _wrap_management(parser_cls._parse_management_command)
    parser_cls._parse_global_conn = _parse_unverified_global_conn
