from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.sanitize import sanitize_raw_text
from fwmigrate.parsers.cisco_asa.model import (
    CiscoDHCPOption,
    CiscoDHCPRelay,
    CiscoDHCPRelayServer,
    CiscoInspectAction,
    CiscoManagementSetting,
)
from fwmigrate.parsers.cisco_asa.model_phase10_17 import (
    CiscoASAConfigPhase10_17,
    CiscoASAContextPhase16,
    CiscoAllocatedInterface,
    CiscoClassMapMatchPhase10,
    CiscoClassMapPhase10,
    CiscoConnectionControlPhase11,
    CiscoDNSServerGroupPhase12,
    CiscoFailoverGroupPhase15,
    CiscoInspectionPolicySection,
    CiscoManagementAccessRulePhase14,
    CiscoMPFConnectionActionPhase11,
    CiscoMPFPoliceActionPhase11,
    CiscoNTPServerPhase14,
    CiscoPolicyMapClassPhase10,
    CiscoPolicyMapPhase10,
    CiscoServicePolicyPhase10,
    CiscoTCPMapPhase11,
    CiscoTCPMapSetting,
    CiscoTrustpointRecord,
)
from fwmigrate.parsers.cisco_asa.reference_validation import ReferenceIssue


_ORIGINALS: Dict[str, Any] = {}
_PATCHED = False

# Current ASA inspection engines plus long-standing engines that still appear in
# running configurations.  Extraction support is intentionally broader than
# target-platform support.
_INSPECT_ENGINES = {
    "ctiqbe", "dcerpc", "diameter", "dns", "esmtp", "ftp", "gtp", "h323",
    "http", "icmp", "icmp-error", "ils", "im", "ip-options", "ipsec-pass-thru",
    "ipv6", "lisp", "m3ua", "mgcp", "netbios", "pptp", "radius-accounting",
    "rsh", "rtsp", "scansafe", "sctp", "sip", "skinny", "snmp", "sqlnet",
    "sunrpc", "tftp", "waas", "xdmcp",
}

# Inspection engines whose inspect action can reference a separately defined
# inspection policy map.  Unknown/legacy parameters are still retained.
_INSPECTION_POLICY_ENGINES = {
    "dcerpc", "diameter", "dns", "esmtp", "ftp", "gtp", "h323", "http", "im",
    "ip-options", "ipsec-pass-thru", "ipv6", "lisp", "m3ua", "mgcp", "netbios",
    "radius-accounting", "rtsp", "scansafe", "sctp", "sip", "skinny", "snmp",
}

_TCP_MAP_KNOWN = {
    "checksum-verification", "exceed-mss", "invalid-ack", "queue-limit",
    "reserved-bits", "sequence-past-window", "syn-data", "tcp-options",
    "ttl-evasion-protection", "urgent-flag", "window-variation",
}


def _line_indent(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" \t"))


def _raw_child_rows(lines: List[str], start: int) -> List[Tuple[int, str, str, int]]:
    rows: List[Tuple[int, str, str, int]] = []
    index = start + 1
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped:
            break
        if stripped.startswith(("!", ":")):
            break
        if not raw[:1].isspace():
            break
        rows.append((index + 1, raw, stripped, _line_indent(raw)))
        index += 1
    return rows


def _header_error_name(prefix: str, line_number: int) -> str:
    return f"{prefix}-invalid-line-{line_number}"


def _parse_class_map_header(parts: List[str], line_number: int) -> Tuple[str, Optional[str], Optional[str], Optional[str], bool]:
    """Return (name, class_map_type, protocol, mode, malformed)."""
    if len(parts) == 2 and parts[0].lower() == "class-map":
        return parts[1], "layer3_4", None, None, False
    if len(parts) == 3 and parts[0].lower() == "class-map" and parts[1].lower() in {"match-any", "match-all"}:
        return parts[2], "layer3_4", None, parts[1].lower(), False
    if len(parts) >= 4 and parts[:2] == ["class-map", "type"]:
        map_type = parts[2].lower()
        if map_type == "inspect":
            # class-map type inspect <application> [match-all|match-any] <name>
            if len(parts) == 5:
                return parts[4], "inspect", parts[3].lower(), "match-all", False
            if len(parts) == 6 and parts[4].lower() in {"match-all", "match-any"}:
                return parts[5], "inspect", parts[3].lower(), parts[4].lower(), False
            return _header_error_name("class-map", line_number), "inspect", parts[3].lower() if len(parts) > 3 else None, None, True
        if map_type == "management":
            # class-map type management <name>
            if len(parts) == 4:
                return parts[3], "management", None, None, False
            return _header_error_name("class-map", line_number), "management", None, None, True
        if map_type == "regex":
            # class-map type regex [match-any] <name>
            if len(parts) == 4:
                return parts[3], "regex", None, None, False
            if len(parts) == 5 and parts[3].lower() in {"match-any", "match-all"}:
                return parts[4], "regex", None, parts[3].lower(), False
            return _header_error_name("class-map", line_number), "regex", None, None, True
        # Preserve an unknown typed header without guessing its name.
        return _header_error_name("class-map", line_number), map_type, None, None, True
    return _header_error_name("class-map", line_number), None, None, None, True


def _parse_class_map_block_phase(self: Any, lines: List[str], index: int) -> CiscoClassMapPhase10:
    line = lines[index].strip()
    parts = line.split()
    name, map_type, protocol, mode, malformed = _parse_class_map_header(parts, index + 1)
    record = CiscoClassMapPhase10(
        name=name,
        class_map_type=map_type,
        inspection_protocol=protocol,
        typed=map_type not in {None, "layer3_4"},
        match_type=mode,
        match_any=(mode == "match-any") if mode else None,
        match_all=(mode == "match-all") if mode else None,
        raw_lines=[sanitize_raw_text(line)],
        source_attributes={"raw_command": sanitize_raw_text(line), "source_line_number": index + 1},
        migration_status="PARTIALLY_NORMALIZED",
        requires_manual_review=True,
    )
    if malformed:
        self._mpf_parse_error(record, index + 1, line, "class-map", "Malformed or unsupported class-map header")

    for line_number, _, child, _ in _raw_child_rows(lines, index):
        safe_child = sanitize_raw_text(child)
        record.raw_lines.append(safe_child)
        lower = child.lower()
        if lower.startswith("description "):
            record.description = child.split(maxsplit=1)[1]
            continue
        if not lower.startswith("match"):
            self._mpf_partial(record, "Unsupported class-map child syntax")
            record.source_attributes.setdefault("unmodeled_lines", []).append(safe_child)
            continue

        record.match_lines.append(safe_child)
        negated = bool(re.match(r"^match\s+not\s+", child, re.I))
        expression = re.sub(r"^match\s+(?:not\s+)?", "", child, flags=re.I).strip()
        if not expression:
            self._mpf_parse_error(record, line_number, child, "class-map", "Malformed class-map match syntax")
            continue

        match = re.fullmatch(r"access-list\s+(\S+)", expression, re.I)
        if match and not negated:
            record.matches.append(CiscoClassMapMatchPhase10(
                match_type="access_list", value=match.group(1), acl_name=match.group(1),
                raw=safe_child, source_order=line_number, expression=expression.split(),
            ))
            continue
        if expression.lower() == "any" and not negated:
            record.matches.append(CiscoClassMapMatchPhase10(
                match_type="any", raw=safe_child, source_order=line_number, expression=["any"],
            ))
            continue
        if expression.lower() == "default-inspection-traffic" and not negated:
            record.matches.append(CiscoClassMapMatchPhase10(
                match_type="default_inspection_traffic", value="default-inspection-traffic",
                raw=safe_child, source_order=line_number, expression=["default-inspection-traffic"],
            ))
            continue
        match = re.fullmatch(r"protocol\s+(\S+)", expression, re.I)
        if match and not negated:
            record.matches.append(CiscoClassMapMatchPhase10(
                match_type="protocol", value=match.group(1), protocol=match.group(1),
                raw=safe_child, source_order=line_number, expression=expression.split(),
            ))
            continue
        match = re.fullmatch(r"port\s+(tcp|udp|sctp)\s+(.+)", expression, re.I)
        if not match:
            match = re.fullmatch(r"(tcp|udp|sctp)\s+(.+)", expression, re.I)
        if match and not negated:
            record.matches.append(CiscoClassMapMatchPhase10(
                match_type="port", value=match.group(2), protocol=match.group(1).lower(),
                port=match.group(2), raw=safe_child, source_order=line_number,
                expression=expression.split(),
            ))
            continue
        match = re.fullmatch(r"class-map\s+(\S+)", expression, re.I)
        if match:
            record.matches.append(CiscoClassMapMatchPhase10(
                match_type="class_map", value=match.group(1), class_map_name=match.group(1),
                negated=negated, raw=safe_child, source_order=line_number,
                expression=expression.split(),
            ))
            self._mpf_partial(record, "Nested class-map reference requires feature validation")
            continue
        if record.class_map_type in {"inspect", "regex"}:
            # Inspection and regex class maps intentionally retain their
            # application-specific expression instead of coercing it to a L3/4 match.
            record.matches.append(CiscoClassMapMatchPhase10(
                match_type="inspection" if record.class_map_type == "inspect" else "regex",
                value=expression, negated=negated, inspection_expression=expression,
                raw=safe_child, source_order=line_number, expression=expression.split(),
            ))
            continue

        self._mpf_partial(record, "Unsupported class-map match syntax")
        record.source_attributes.setdefault("unmodeled_lines", []).append(safe_child)
    return record


def _parse_policy_map_header(parts: List[str], line_number: int) -> Tuple[str, Optional[str], Optional[str], bool]:
    if len(parts) == 2 and parts[0].lower() == "policy-map":
        return parts[1], "layer3_4", None, False
    if len(parts) == 5 and parts[:3] == ["policy-map", "type", "inspect"]:
        return parts[4], "inspect", parts[3].lower(), False
    return _header_error_name("policy-map", line_number), None, None, True


def _parse_policy_map_block_phase(self: Any, lines: List[str], index: int) -> CiscoPolicyMapPhase10:
    line = lines[index].strip()
    parts = line.split()
    name, map_type, protocol, malformed = _parse_policy_map_header(parts, index + 1)
    record = CiscoPolicyMapPhase10(
        name=name, policy_map_type=map_type, inspection_protocol=protocol,
        typed=map_type == "inspect", raw_lines=[sanitize_raw_text(line)],
        source_attributes={"raw_command": sanitize_raw_text(line), "source_line_number": index + 1},
        migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
    )
    if malformed:
        self._mpf_parse_error(record, index + 1, line, "policy-map", "Malformed or unsupported policy-map header")

    rows = _raw_child_rows(lines, index)
    if map_type == "inspect" and not malformed:
        if not rows:
            return record
        top_indent = min(row[3] for row in rows)
        current: Optional[CiscoInspectionPolicySection] = None
        for line_number, _, child, indent in rows:
            safe = sanitize_raw_text(child)
            record.raw_lines.append(safe)
            lower = child.lower()
            if indent == top_indent:
                if lower.startswith("description "):
                    record.description = child.split(maxsplit=1)[1]
                    current = None
                    continue
                if lower == "parameters" or lower.startswith("parameters "):
                    current = CiscoInspectionPolicySection(
                        kind="parameters", header=safe, source_order=line_number,
                        raw_lines=[safe], source_attributes={"indent": indent},
                    )
                    record.inspection_sections.append(current)
                    continue
                class_match = re.fullmatch(r"class\s+(\S+)", child, re.I)
                if class_match:
                    current = CiscoInspectionPolicySection(
                        kind="class", header=safe, source_order=line_number,
                        class_name=class_match.group(1), raw_lines=[safe],
                        source_attributes={"indent": indent},
                    )
                    record.inspection_sections.append(current)
                    continue
                if lower.startswith("match "):
                    negated = bool(re.match(r"^match\s+not\s+", child, re.I))
                    expression = re.sub(r"^match\s+(?:not\s+)?", "", child, flags=re.I).strip()
                    if not expression:
                        self._mpf_parse_error(record, line_number, child, "policy-map", "Malformed typed inspection match")
                        current = None
                        continue
                    current = CiscoInspectionPolicySection(
                        kind="match", header=safe, source_order=line_number,
                        match_expression=expression, negated=negated, raw_lines=[safe],
                        source_attributes={"indent": indent},
                    )
                    record.inspection_sections.append(current)
                    continue
                current = CiscoInspectionPolicySection(
                    kind="raw", header=safe, source_order=line_number,
                    raw_lines=[safe], source_attributes={"indent": indent},
                )
                record.inspection_sections.append(current)
                self._mpf_partial(record, "Unsupported typed inspection policy child syntax")
                continue

            if current is None:
                self._mpf_partial(record, "Orphan nested inspection policy command")
                record.source_attributes.setdefault("unmodeled_lines", []).append(safe)
                continue
            current.raw_lines.append(safe)
            if current.kind == "parameters":
                current.parameters.append(safe)
                record.parameter_lines.append(safe)
            else:
                current.actions.append(safe)
        return record

    current: Optional[CiscoPolicyMapClassPhase10] = None
    for line_number, _, child, _ in rows:
        safe_child = sanitize_raw_text(child)
        record.raw_lines.append(safe_child)
        if child.lower().startswith("description ") and current is None:
            record.description = child.split(maxsplit=1)[1]
            continue
        if child.lower() == "class" or child.lower().startswith("class "):
            class_parts = child.split()
            class_name = class_parts[1] if len(class_parts) == 2 else _header_error_name("class", line_number)
            current = CiscoPolicyMapClassPhase10(
                class_name=class_name, source_order=line_number,
                raw_lines=[safe_child], migration_status="PARTIALLY_NORMALIZED",
                requires_manual_review=True, source_attributes={"raw_header": safe_child},
            )
            record.classes.append(current)
            record.class_sections.append(safe_child)
            if len(class_parts) != 2:
                self._mpf_parse_error(current, line_number, child, "policy-map", "Malformed policy-map class header")
            continue
        if current is None:
            self._mpf_partial(record, "Unsupported policy-map child syntax")
            record.source_attributes.setdefault("unmodeled_lines", []).append(safe_child)
            continue
        current.raw_lines.append(safe_child)
        self._parse_mpf_action(current, child, line_number)
    return record


def _parse_mpf_action_phase(self: Any, section: CiscoPolicyMapClassPhase10, line: str, line_number: int) -> None:
    safe = sanitize_raw_text(line)
    stripped = line.strip()
    negated = stripped.lower().startswith("no ")
    effective = stripped[3:].strip() if negated else stripped
    parts = effective.split()
    lower = effective.lower()

    if lower == "inspect" or lower.startswith("inspect "):
        if len(parts) < 2:
            self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed inspect action: missing protocol")
            return
        protocol = parts[1].lower()
        action = CiscoInspectAction(protocol=protocol, raw=safe, source_order=line_number)
        extras = parts[2:]
        if negated:
            action.parameters.append("no")
            action.migration_status = "PARTIALLY_NORMALIZED"
            action.requires_manual_review = True
            action.review_reasons.append("Negated inspect action retained for effective-state review")
        if protocol not in _INSPECT_ENGINES:
            action.parameters.extend(extras)
            action.migration_status = "PARTIALLY_NORMALIZED"
            action.requires_manual_review = True
            action.review_reasons.append("Unknown inspect protocol retained as structured source data")
            section.inspect_actions.append(action)
            return
        if protocol == "icmp" and extras[:1] == ["error"]:
            action.parameters.append("error")
            extras = extras[1:]
        elif protocol == "h323" and extras and extras[0].lower() in {"h225", "ras"}:
            action.parameters.append(extras[0])
            extras = extras[1:]
        if extras and extras[0].lower() == "policy":
            if len(extras) < 2:
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed inspect policy reference")
                return
            action.policy_name = extras[1]
            action.parameters.extend(extras[2:])
        elif extras and protocol in _INSPECTION_POLICY_ENGINES:
            # ASA inspect actions normally reference a policy map directly by
            # name. Preserve extra tokens rather than rejecting version-specific
            # variants.
            action.policy_name = extras[0]
            action.parameters.extend(extras[1:])
        elif extras:
            action.parameters.extend(extras)
        if action.policy_name:
            action.migration_status = "PARTIALLY_NORMALIZED"
            action.requires_manual_review = True
            action.review_reasons.append("Referenced inspection policy requires target review")
        section.inspect_actions.append(action)
        return

    if lower.startswith("set connection") or lower.startswith("no set connection"):
        action = self._parse_connection_action(section, stripped, line_number)
        section.connection_actions.append(action)
        if action.advanced_options:
            section.tcp_map = action.advanced_options
        return
    if lower.startswith("tcp-map"):
        if len(parts) == 2:
            section.tcp_map = parts[1]
        else:
            self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed tcp-map reference")
        return
    if lower.startswith("police") or lower.startswith("no police"):
        section.police_actions.append(self._parse_police_action(section, stripped, line_number))
        return
    self._mpf_partial(section, "Unsupported policy-map class action syntax")
    section.source_attributes.setdefault("unmodeled_lines", []).append(safe)


def _parse_connection_action_phase(self: Any, section: Any, line: str, line_number: int) -> CiscoMPFConnectionActionPhase11:
    safe = sanitize_raw_text(line)
    parts = line.split()
    negated = parts[:1] == ["no"]
    if negated:
        parts = parts[1:]
    action = CiscoMPFConnectionActionPhase11(raw=safe, source_order=line_number, negated=negated)
    if len(parts) < 3 or [part.lower() for part in parts[:2]] != ["set", "connection"]:
        self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed set connection action")
        return action

    numeric = {
        "conn-max": "max_connections",
        "embryonic-conn-max": "max_embryonic",
        "per-client-max": "per_client_max",
        "per-client-embryonic-max": "per_client_embryonic",
        "syn-cookie-mss": "syn_cookie_mss",
    }
    position = 2
    while position < len(parts):
        key = parts[position].lower()
        if key in numeric:
            if position + 1 >= len(parts) or not parts[position + 1].isdigit():
                self._mpf_parse_error(section, line_number, line, "policy-map", f"Malformed set connection {key} value")
                action.raw_options.extend(parts[position:])
                break
            setattr(action, numeric[key], int(parts[position + 1]))
            position += 2
            continue
        if key == "random-sequence-number":
            if position + 1 >= len(parts) or parts[position + 1].lower() not in {"enable", "disable"}:
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed random-sequence-number value")
                action.raw_options.extend(parts[position:])
                break
            action.random_sequence_number = parts[position + 1].lower()
            position += 2
            continue
        if key == "timeout":
            if position + 2 >= len(parts):
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed set connection timeout")
                action.raw_options.extend(parts[position:])
                break
            timeout_kind, value = parts[position + 1].lower(), parts[position + 2]
            action.timeouts[timeout_kind] = value
            if timeout_kind == "embryonic":
                action.timeout_embryonic = value
            position += 3
            continue
        if key in {"advanced-options", "tcp-map"}:
            if position + 1 >= len(parts):
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed TCP normalization map reference")
                break
            action.advanced_options = parts[position + 1]
            position += 2
            continue
        if key == "tcp-intercept":
            if position + 1 < len(parts):
                action.tcp_intercept = parts[position + 1]
                position += 2
            else:
                action.tcp_intercept = "enable"
                position += 1
            self._mpf_partial(section, "Legacy TCP intercept option retained for review")
            continue
        self._mpf_partial(section, "Unsupported set connection action syntax")
        action.review_reasons.append(f"Unsupported set connection option: {parts[position]}")
        action.raw_options.extend(parts[position:])
        break
    return action


def _parse_police_action_phase(self: Any, section: Any, line: str, line_number: int) -> CiscoMPFPoliceActionPhase11:
    safe = sanitize_raw_text(line)
    parts = line.split()
    negated = parts[:1] == ["no"]
    if negated:
        parts = parts[1:]
    action = CiscoMPFPoliceActionPhase11(raw=safe, source_order=line_number, negated=negated)
    if not parts or parts[0].lower() != "police":
        self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed police action")
        return action
    values = parts[1:]
    if values and values[0].lower() in {"input", "output"}:
        action.direction = values.pop(0).lower()
    if values and values[0].lower() == "rate":
        values.pop(0)
    if not values or not values[0].isdigit():
        self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed police rate")
        action.raw_options = values
        return action
    action.rate = int(values.pop(0))
    if values and values[0].lower() == "burst":
        values.pop(0)
    if values and values[0].isdigit():
        action.burst = int(values.pop(0))
    while values:
        key = values.pop(0).lower()
        if key in {"conform-action", "exceed-action"} and values:
            value = values.pop(0)
            if key == "conform-action":
                action.conform_action = value
            else:
                action.exceed_action = value
            continue
        action.raw_options.append(key)
        self._mpf_partial(section, "Unsupported police action modifier")
    return action


def _parse_tcp_map_block_phase(self: Any, lines: List[str], index: int) -> CiscoTCPMapPhase11:
    line = lines[index].strip()
    parts = line.split()
    name = parts[1] if len(parts) == 2 and parts[0].lower() == "tcp-map" else _header_error_name("tcp-map", index + 1)
    record = CiscoTCPMapPhase11(
        name=name, raw_lines=[sanitize_raw_text(line)],
        source_attributes={"raw_command": sanitize_raw_text(line), "source_line_number": index + 1},
        migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
    )
    if len(parts) != 2:
        self._mpf_parse_error(record, index + 1, line, "tcp-map", "Malformed tcp-map header")
    for line_number, _, child, _ in _raw_child_rows(lines, index):
        safe = sanitize_raw_text(child)
        record.raw_lines.append(safe)
        tokens = child.split()
        negated = tokens[:1] == ["no"]
        if negated:
            tokens = tokens[1:]
        if not tokens:
            self._mpf_parse_error(record, line_number, child, "tcp-map", "Malformed tcp-map child")
            continue
        key, values = tokens[0].lower(), tokens[1:]
        supported = key in _TCP_MAP_KNOWN
        entry = CiscoTCPMapSetting(
            key=key, values=values, negated=negated, raw=safe,
            source_order=line_number, supported=supported,
        )
        record.setting_entries.append(entry)
        record.setting_history.setdefault(key, []).append(safe)
        if key == "queue-limit" and not negated:
            if len(values) != 1 or not values[0].isdigit():
                self._mpf_parse_error(record, line_number, child, "tcp-map", "Malformed tcp-map queue-limit")
            else:
                record.settings[key] = int(values[0])
            continue
        if negated:
            record.settings[key] = False
        elif not values:
            record.settings[key] = True
        elif len(values) == 1:
            record.settings[key] = values[0]
        else:
            record.settings[key] = list(values)
        if not supported:
            self._mpf_partial(record, "Unsupported tcp-map child syntax retained as structured raw setting")
            record.source_attributes.setdefault("unmodeled_lines", []).append(safe)
    return record


def _parse_service_policy_line_phase(self: Any, line: str, line_number: int) -> CiscoServicePolicyPhase10:
    safe = sanitize_raw_text(line)
    parts = line.split()
    negated = parts[:1] == ["no"]
    if negated:
        parts = parts[1:]
    if not parts or parts[0].lower() != "service-policy":
        return CiscoServicePolicyPhase10(
            name=_header_error_name("service-policy", line_number), raw_lines=[safe],
            source_order=line_number, migration_status="PARSE_ERROR", requires_manual_review=True,
            review_reasons=["Malformed service-policy command"],
        )
    policy_name = parts[1] if len(parts) > 1 else None
    remainder = parts[2:]
    fail_close = False
    if remainder and remainder[-1].lower() == "fail-close":
        fail_close = True
        remainder = remainder[:-1]
    scope = None
    interface = None
    if remainder == ["global"]:
        scope = "global"
    elif len(remainder) == 2 and remainder[0].lower() == "interface":
        scope, interface = "interface", remainder[1]
    record = CiscoServicePolicyPhase10(
        name=policy_name or _header_error_name("service-policy", line_number),
        policy_name=policy_name, attachment=scope, scope=scope,
        global_attachment=scope == "global", interface=interface,
        enabled=not negated, negated=negated, fail_close=fail_close,
        source_order=line_number, raw_lines=[safe],
        source_attributes={"raw_command": safe, "negated": negated},
        migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False,
    )
    if not policy_name:
        self._mpf_parse_error(record, line_number, line, "service-policy", "Malformed service-policy: missing policy name")
    elif scope is None:
        self._mpf_parse_error(record, line_number, line, "service-policy", "Malformed or unsupported service-policy attachment")
    return record


def _parse_threat_detection_phase(self: Any, line: str, line_number: int) -> CiscoConnectionControlPhase11:
    parts = line.split()
    negated = parts[:1] == ["no"]
    if negated:
        parts = parts[1:]
    item = CiscoConnectionControlPhase11(
        name=f"threat-detection:{line_number}", setting="threat-detection",
        control_type="threat_detection", raw_lines=[sanitize_raw_text(line)],
        source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line), "negated": negated},
        migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False,
        negated=negated, enabled=not negated,
    )
    if len(parts) < 2 or parts[0].lower() != "threat-detection":
        item.migration_status = "PARSE_ERROR"
        item.requires_manual_review = True
        item.review_reasons.append("Malformed threat-detection command")
        self._record_diagnostic(line_number, line, "Malformed threat-detection command", "threat-detection")
        return item
    item.threat_detection_type = parts[1].lower()
    params = parts[2:]
    item.raw_parameters = list(params)
    item.values = list(params)

    if item.threat_detection_type == "statistics":
        if params and params[0].lower() in {"access-list", "host", "port", "protocol", "tcp-intercept"}:
            item.statistics_target = params.pop(0).lower()
        pos = 0
        allowed = {"number-of-rate", "rate-interval", "burst-rate", "average-rate"}
        while pos < len(params):
            key = params[pos].lower()
            if key not in allowed or pos + 1 >= len(params):
                item.requires_manual_review = True
                item.review_reasons.append("Unsupported threat-detection statistics parameter")
                break
            value = params[pos + 1]
            if not value.isdigit():
                item.migration_status = "PARSE_ERROR"
                item.requires_manual_review = True
                item.review_reasons.append(f"Threat-detection {key} must be numeric")
                self._record_diagnostic(line_number, line, f"Malformed threat-detection {key}", "threat-detection")
                break
            numeric = int(value)
            if key == "number-of-rate":
                item.number_of_rate = numeric
            elif key == "rate-interval":
                item.rate_interval = numeric
            elif key == "burst-rate":
                item.burst_rate = numeric
                item.burst = numeric
            elif key == "average-rate":
                item.average_rate = numeric
                item.rate = numeric
            pos += 2
        return item
    if item.threat_detection_type in {"basic-threat", "scanning-threat"}:
        # These families have additional version-specific forms. Their explicit
        # state is typed here and the remaining tokens are preserved verbatim.
        if params:
            item.requires_manual_review = True
            item.review_reasons.append("Threat-detection family has preserved version-specific parameters")
        return item
    item.requires_manual_review = True
    item.review_reasons.append("Threat-detection variant preserved without semantic coercion")
    return item


def _extract_explicit_interface(values: List[str]) -> Tuple[List[str], Optional[str], bool]:
    lowered = [value.lower() for value in values]
    if "interface" not in lowered:
        return list(values), None, False
    pos = lowered.index("interface")
    if pos + 1 >= len(values):
        return list(values), None, True
    interface = values[pos + 1]
    return values[:pos] + values[pos + 2 :], interface, False


def _parse_dhcpd_command_phase(self: Any, line: str, line_number: int) -> None:
    safe = sanitize_raw_text(line)
    parts = line.split()
    negated = parts[:1] == ["no"]
    if negated:
        parts = parts[1:]
    if len(parts) < 2 or parts[0].lower() != "dhcpd":
        self._record_diagnostic(line_number, line, "Malformed DHCP command", "dhcpd")
        return
    command = parts[1].lower()
    values, explicit_interface, malformed_interface = _extract_explicit_interface(parts[2:])
    if malformed_interface:
        self._record_diagnostic(line_number, line, "Malformed DHCP interface clause", "dhcpd")

    interface = explicit_interface
    # Command families have different ASA grammars. Address and enable use a
    # trailing interface name; DNS/domain can use an explicit `interface NAME`
    # clause and must not guess an interface from an arbitrary final token.
    if command == "address" and interface is None and values:
        interface = values[-1]
        values = values[:-1]
    elif command == "enable" and interface is None and values:
        interface = values[0]
        values = values[1:]

    item = self._dhcp_server(interface, line_number)
    item.raw_lines.append(safe)
    item.source_attributes.setdefault("raw_commands", []).append(safe)
    item.source_attributes.setdefault("command_history", []).append({"line": line_number, "negated": negated, "command": command})

    if command == "address":
        pool_expression = "".join(values) if len(values) == 3 and values[1] == "-" else (values[0] if len(values) == 1 else "")
        if negated:
            item.pool = item.pool_start = item.pool_end = None
            return
        if "-" not in pool_expression:
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            item.review_reasons.append("Malformed DHCP address pool")
            self._record_diagnostic(line_number, line, "Malformed DHCP address pool", "dhcpd")
            return
        start, end = pool_expression.split("-", 1)
        try:
            start_ip, end_ip = ipaddress.ip_address(start), ipaddress.ip_address(end)
            valid = start_ip.version == 4 and end_ip.version == 4 and start_ip <= end_ip
        except ValueError:
            valid = False
        if not valid:
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            item.review_reasons.append("Invalid or reversed DHCP address pool")
            self._record_diagnostic(line_number, line, "Invalid or reversed DHCP address pool", "dhcpd")
            return
        item.pool = pool_expression
        item.pool_start, item.pool_end = start, end
        return
    if command == "enable":
        item.interface = interface or item.interface
        item.enabled = not negated
        if not interface:
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            self._record_diagnostic(line_number, line, "DHCP enable requires an interface", "dhcpd")
        return
    if command == "dns":
        if negated:
            item.dns_servers = []
            return
        if not values:
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            self._record_diagnostic(line_number, line, "Malformed DHCP DNS server", "dhcpd")
            return
        parsed: List[str] = []
        for value in values:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                item.migration_status = "PARSE_ERROR"
                item.requires_manual_review = True
                item.review_reasons.append(f"Invalid DHCP DNS server: {value}")
                self._record_diagnostic(line_number, line, "Malformed DHCP DNS server", "dhcpd")
                continue
            parsed.append(str(address))
        item.dns_servers.extend(value for value in parsed if value not in item.dns_servers)
        return
    if command == "domain":
        if negated:
            item.domain_name = None
        elif values:
            item.domain_name = " ".join(values)
        else:
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            self._record_diagnostic(line_number, line, "Malformed DHCP domain", "dhcpd")
        return
    if command == "lease":
        if negated:
            item.lease_seconds = None
        elif len(values) == 1 and values[0].isdigit():
            item.lease_seconds = int(values[0])
        else:
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            self._record_diagnostic(line_number, line, "Malformed DHCP lease", "dhcpd")
        return
    if command == "option" and len(values) >= 2:
        item.options.append(CiscoDHCPOption(code=values[0], value=" ".join(values[1:]), raw=safe, source_order=line_number))
        return
    item.requires_manual_review = True
    item.review_reasons.append("Unsupported DHCP command retained")
    item.source_attributes.setdefault("unmodeled_lines", []).append(safe)


def _parse_management_command_phase(self: Any, line: str, line_number: int) -> None:
    safe = sanitize_raw_text(line)
    parts = line.split()
    lower = line.lower()
    negated = parts[:1] == ["no"]
    effective_parts = parts[1:] if negated else parts
    effective_lower = " ".join(effective_parts).lower()

    if effective_lower.startswith("http server"):
        self._legacy_management(line)
        http = self.config.http_server
        http.raw_lines.append(safe)
        http.source_order = http.source_order or line_number
        if len(effective_parts) >= 3 and effective_parts[:3] == ["http", "server", "enable"]:
            http.enabled = not negated
            if len(effective_parts) == 4:
                if effective_parts[3].isdigit() and 1 <= int(effective_parts[3]) <= 65535:
                    http.port = int(effective_parts[3])
                else:
                    http.migration_status = "PARSE_ERROR"
                    http.requires_manual_review = True
                    http.review_reasons.append("Invalid HTTP server port")
                    self._record_diagnostic(line_number, line, "Invalid HTTP server port", "http")
            elif len(effective_parts) > 4:
                http.migration_status = "PARSE_ERROR"
                http.requires_manual_review = True
                self._record_diagnostic(line_number, line, "Malformed HTTP server enable command", "http")
            return
        if len(effective_parts) >= 3 and effective_parts[:3] in (["http", "server", "idle-timeout"], ["http", "server", "session-timeout"]):
            field = "idle_timeout" if effective_parts[2] == "idle-timeout" else "session_timeout"
            if negated:
                setattr(http, field, None)
            elif len(effective_parts) == 4 and effective_parts[3].isdigit():
                setattr(http, field, int(effective_parts[3]))
            else:
                http.migration_status = "PARSE_ERROR"
                http.requires_manual_review = True
                self._record_diagnostic(line_number, line, f"Malformed HTTP server {effective_parts[2]}", "http")
            return
        http.requires_manual_review = True
        http.review_reasons.append("Unsupported HTTP server setting retained")
        return

    command = effective_parts[0].lower() if effective_parts else ""
    if command in {"ssh", "http", "telnet"} and len(effective_parts) >= 3:
        # Keep protocol-wide settings such as `ssh timeout` separate from source
        # access rules.
        if effective_parts[1].lower() in {"timeout", "version", "key-exchange", "cipher", "authentication"}:
            return _ORIGINALS["management"](self, line, line_number)
        if ":" in effective_parts[1] and "/" in effective_parts[1] and len(effective_parts) == 3:
            try:
                network = ipaddress.ip_network(effective_parts[1], strict=False)
            except ValueError:
                network = None
            item = CiscoManagementAccessRulePhase14(
                name=f"{command}:{line_number}", protocol=command,
                source=effective_parts[1], mask_or_prefix=str(network.prefixlen) if network else None,
                interface=effective_parts[2], address_family="ipv6", negated=negated,
                raw_line=safe, raw_lines=[safe], source_order=line_number,
                source_attributes={"raw_command": safe, "negated": negated},
            )
            if network is None or network.version != 6:
                item.migration_status = "PARSE_ERROR"
                item.requires_manual_review = True
                item.review_reasons.append("Invalid management IPv6 prefix")
                self._record_diagnostic(line_number, line, "Invalid management IPv6 prefix", command)
            self.config.management_access_rules.append(item)
            self._legacy_management(line)
            return
    return _ORIGINALS["management"](self, line, line_number)


def _build_context_ownership_phase(lines: List[str]) -> Dict[int, Optional[str]]:
    admin_name: Optional[str] = None
    for raw in lines:
        if raw[:1].isspace():
            continue
        match = re.fullmatch(r"admin-context\s+(\S+)", raw.strip(), re.I)
        if match:
            admin_name = match.group(1)
        elif re.fullmatch(r"no\s+admin-context(?:\s+\S+)?", raw.strip(), re.I):
            admin_name = None

    ownership: Dict[int, Optional[str]] = {}
    active: Optional[str] = None
    for index, raw in enumerate(lines):
        line = raw.strip()
        ownership[index + 1] = active
        if not line or line.startswith(("!", ":")) or raw[:1].isspace():
            continue
        switch = re.fullmatch(r"changeto\s+context\s+(\S+)", line, re.I)
        if switch:
            active = switch.group(1)
            ownership[index + 1] = active
            continue
        if re.fullmatch(r"changeto\s+system", line, re.I):
            active = None
            ownership[index + 1] = None
            continue
        if re.fullmatch(r"changeto\s+admin", line, re.I):
            active = admin_name
            ownership[index + 1] = active
            continue
        context = re.fullmatch(r"context\s+(\S+)", line, re.I)
        if not context:
            continue
        next_index = index + 1
        while next_index < len(lines) and not lines[next_index].strip():
            next_index += 1
        has_definition_children = (
            next_index < len(lines)
            and not lines[next_index].strip().startswith(("!", ":"))
            and bool(lines[next_index][:1].isspace())
        )
        active = None if has_definition_children else context.group(1)
        ownership[index + 1] = active
    return ownership


def _postprocess_dns(self: Any) -> None:
    lines = self.raw_lines
    for index, raw in enumerate(lines):
        if raw[:1].isspace():
            continue
        line = raw.strip()
        group_match = re.fullmatch(r"dns\s+server-group\s+(\S+)", line, re.I)
        if group_match:
            name = group_match.group(1)
            context = self._line_contexts.get(index + 1)
            group = next((g for g in self.config.dns_server_groups if g.name == name and getattr(g, "source_context", None) == context), None)
            if group is None:
                group = CiscoDNSServerGroupPhase12(name=name, source_context=context, raw_lines=[sanitize_raw_text(line)], source_order=index + 1)
                self.config.dns_server_groups.append(group)
            for line_number, _, child, _ in _raw_child_rows(lines, index):
                safe = sanitize_raw_text(child)
                if safe not in group.child_order:
                    group.child_order.append(safe)
                tokens = child.split()
                if not tokens:
                    continue
                key, values = tokens[0].lower(), tokens[1:]
                group.raw_settings.append({"key": key, "values": values, "line_number": line_number, "raw": safe})
                if key == "retries" and len(values) == 1 and values[0].isdigit():
                    group.retries = int(values[0])
                elif key == "timeout" and len(values) == 1 and values[0].isdigit():
                    group.timeout = int(values[0])
                elif key in {"expire-entry-timer", "poll-timer"}:
                    numeric = values[-1] if values else ""
                    if numeric.isdigit():
                        setattr(group, "expire_entry_timer" if key == "expire-entry-timer" else "poll_timer", int(numeric))
                    else:
                        group.requires_manual_review = True
                        group.review_reasons.append(f"Malformed DNS {key}")
                elif key not in {"name-server", "domain-name"}:
                    group.requires_manual_review = True
                    if "Unsupported DNS server-group child retained" not in group.review_reasons:
                        group.review_reasons.append("Unsupported DNS server-group child retained")
            continue
        default_match = re.fullmatch(r"dns-group\s+(\S+)", line, re.I)
        if default_match:
            self.config.dns_settings.default_server_group = default_match.group(1)
            self.config.dns_settings.command_history.append(sanitize_raw_text(line))


def _postprocess_interface_dhcprelay(self: Any) -> None:
    lines = self.raw_lines
    relay = next((item for item in self.config.dhcp_relays if item.name == "dhcprelay"), None)
    if relay is None:
        relay = CiscoDHCPRelay(name="dhcprelay", migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False)
    found = False
    for index, raw in enumerate(lines):
        if raw[:1].isspace():
            continue
        match = re.fullmatch(r"interface\s+(\S+)", raw.strip(), re.I)
        if not match:
            continue
        interface_name = match.group(1)
        interface_obj = next((item for item in self.config.interfaces if item.name == interface_name and getattr(item, "source_context", None) == self._line_contexts.get(index + 1)), None)
        for line_number, _, child, _ in _raw_child_rows(lines, index):
            server = re.fullmatch(r"dhcprelay\s+server\s+(\S+)", child, re.I)
            if server:
                found = True
                address = server.group(1)
                entry = CiscoDHCPRelayServer(server=address, interface=interface_name, raw=sanitize_raw_text(child), source_order=line_number)
                relay.server_entries.append(entry)
                relay.servers.append(address)
                relay.server = relay.server or address
                relay.interface = relay.interface or interface_name
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    relay.migration_status = "PARSE_ERROR"
                    relay.requires_manual_review = True
                    relay.review_reasons.append("DHCP relay server must be an IP address")
                    self._record_diagnostic(line_number, child, "Malformed DHCP relay server", "dhcprelay")
                if interface_obj is not None:
                    unmodeled = interface_obj.source_attributes.get("unmodeled_lines", [])
                    if sanitize_raw_text(child) in unmodeled:
                        unmodeled.remove(sanitize_raw_text(child))
                continue
            info = re.fullmatch(r"dhcprelay\s+information\s+(.+)", child, re.I)
            if info:
                found = True
                relay.options.append(f"{interface_name}: information {info.group(1)}")
                if interface_obj is not None:
                    unmodeled = interface_obj.source_attributes.get("unmodeled_lines", [])
                    if sanitize_raw_text(child) in unmodeled:
                        unmodeled.remove(sanitize_raw_text(child))
    if found and relay not in self.config.dhcp_relays:
        self.config.dhcp_relays.append(relay)


def _postprocess_trustpoints(self: Any) -> None:
    self.config.trustpoint_records.clear()
    lines = self.raw_lines
    for index, raw in enumerate(lines):
        if raw[:1].isspace():
            continue
        line = raw.strip()
        match = re.fullmatch(r"crypto\s+ca\s+trustpoint\s+(\S+)", line, re.I)
        if not match:
            continue
        name = match.group(1)
        record = CiscoTrustpointRecord(
            name=name, source_context=self._line_contexts.get(index + 1), source_order=index + 1,
            raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": sanitize_raw_text(line)},
        )
        for _, _, child, _ in _raw_child_rows(lines, index):
            tokens = child.split()
            if not tokens:
                continue
            key = tokens[0].lower()
            # Never retain credential, private-key, PIN, or password payloads.
            if key in {"password", "key", "pin", "private-key"}:
                record.source_attributes["secret_present"] = True
                record.raw_lines.append(f"{key} <redacted>")
                continue
            safe = sanitize_raw_text(child)
            record.raw_lines.append(safe)
            values = tokens[1:]
            if key == "enrollment":
                record.enrollment = " ".join(values)
            elif key == "subject-name":
                record.subject_name = " ".join(values)
            elif key in {"keypair", "keypair-reference"} and values:
                record.keypair_reference = values[0]
            elif key == "revocation-check":
                record.revocation_check = values
            elif key.startswith("validation"):
                record.validation_settings.append(safe)
            elif key.startswith("crl"):
                record.crl_settings.append(safe)
            elif key.startswith("ocsp"):
                record.ocsp_settings.append(safe)
            else:
                record.source_attributes.setdefault("unmodeled_lines", []).append(safe)
        self.config.trustpoint_records.append(record)
        if name not in self.config.trustpoints:
            self.config.trustpoints.append(name)

    # Certificate chain bodies can be very large and may contain sensitive key
    # material in malformed exports. Preserve presence/reference, not body text.
    for index, raw in enumerate(lines):
        if raw[:1].isspace():
            continue
        match = re.match(r"crypto\s+ca\s+certificate\s+chain\s+(\S+)", raw.strip(), re.I)
        if not match:
            continue
        name = match.group(1)
        context = self._line_contexts.get(index + 1)
        record = next((item for item in self.config.trustpoint_records if item.name == name and item.source_context == context), None)
        if record:
            record.certificate_present = True
            record.certificate_references.append(sanitize_raw_text(raw.strip()))


def _postprocess_contexts(self: Any) -> None:
    system = self.config.multi_context_system
    for context in self.config.contexts:
        context.admin_context = None
        context.allocated_interface_entries = []
    lines = self.raw_lines
    valid_admin_seen = False
    for index, raw in enumerate(lines):
        if raw[:1].isspace():
            continue
        line = raw.strip()
        admin = re.fullmatch(r"admin-context\s+(\S+)", line, re.I)
        if admin:
            valid_admin_seen = True
            system.admin_context_name = admin.group(1)
            system.raw_lines.append(sanitize_raw_text(line))
        elif re.fullmatch(r"no\s+admin-context(?:\s+\S+)?", line, re.I):
            valid_admin_seen = True
            system.admin_context_name = None
            system.raw_lines.append(sanitize_raw_text(line))
        context_match = re.fullmatch(r"context\s+(\S+)", line, re.I)
        if not context_match:
            continue
        context = next((item for item in self.config.contexts if item.name == context_match.group(1)), None)
        if context is None:
            continue
        for line_number, _, child, _ in _raw_child_rows(lines, index):
            tokens = child.split()
            if not tokens or tokens[0].lower() != "allocate-interface" or len(tokens) < 2:
                continue
            physical = tokens[1]
            mapped = tokens[2] if len(tokens) >= 3 else None
            entry = CiscoAllocatedInterface(
                physical_interface=physical, mapped_name=mapped,
                range_expression=physical if "-" in physical else None,
                source_order=line_number, raw=sanitize_raw_text(child),
            )
            context.allocated_interface_entries.append(entry)
    if valid_admin_seen and system.admin_context_name:
        target = next((item for item in self.config.contexts if item.name == system.admin_context_name), None)
        system.admin_context_resolved = target is not None
        if target is not None:
            target.admin_context = True
        else:
            system.review_reasons.append(f"Unresolved admin-context reference: {system.admin_context_name}")
    elif valid_admin_seen:
        system.admin_context_resolved = None


def _postprocess_failover_groups(self: Any) -> None:
    lines = self.raw_lines
    for index, raw in enumerate(lines):
        if raw[:1].isspace():
            continue
        match = re.fullmatch(r"failover\s+group\s+(\d+)", raw.strip(), re.I)
        if not match:
            continue
        group_id = int(match.group(1))
        group = next((item for item in self.config.failover_config.failover_groups if item.group_id == group_id), None)
        if group is None:
            group = CiscoFailoverGroupPhase15(name=f"failover-group:{group_id}", group_id=group_id, source_order=index + 1)
            self.config.failover_config.failover_groups.append(group)
        for _, _, child, _ in _raw_child_rows(lines, index):
            safe = sanitize_raw_text(child)
            if safe not in group.raw_children:
                group.raw_children.append(safe)
            tokens = child.split()
            lower = child.lower()
            if lower in {"primary", "secondary"}:
                group.unit_role = lower
            elif lower == "preempt":
                group.preempt = True
            elif lower == "no preempt":
                group.preempt = False
            elif lower == "replication http":
                group.replication_http = True
            elif lower == "no replication http":
                group.replication_http = False
            elif tokens[:1] == ["priority"] and len(tokens) == 2 and tokens[1].isdigit():
                group.priority = int(tokens[1])
            elif tokens[:1] == ["interface-policy"] and len(tokens) >= 2:
                group.interface_policy = " ".join(tokens[1:])
            elif tokens[:1] == ["polltime"] and len(tokens) >= 2:
                group.polltime = " ".join(tokens[1:])


def _postprocess_no_service_policies(self: Any) -> None:
    existing = {(item.source_order, item.raw_lines[0] if item.raw_lines else "") for item in self.config.service_policies}
    for line_number, raw in enumerate(self.raw_lines, 1):
        line = raw.strip()
        if raw[:1].isspace() or not line.lower().startswith("no service-policy "):
            continue
        safe = sanitize_raw_text(line)
        if (line_number, safe) in existing:
            continue
        record = self._with_source_context(self._parse_service_policy_line(line, line_number), line_number)
        self.config.service_policies.append(record)
        self.config.unsupported_commands = [
            item for item in self.config.unsupported_commands
            if not (item.get("line_number") == line_number and item.get("raw_line") == safe)
        ]


def _postprocess_http_server(self: Any) -> None:
    # Some `no http server ...` forms are routed through the generic no-command
    # path by the legacy parser. Replay only server-global commands that were not
    # already handled so final state remains deterministic.
    seen = set(self.config.http_server.raw_lines)
    for line_number, raw in enumerate(self.raw_lines, 1):
        line = raw.strip()
        if raw[:1].isspace():
            continue
        effective = line[3:].strip() if line.lower().startswith("no ") else line
        if not effective.lower().startswith("http server "):
            continue
        safe = sanitize_raw_text(line)
        if safe in seen:
            continue
        _parse_management_command_phase(self, line, line_number)
        seen.add(safe)


def _extend_reference_validation(original_validate: Any):
    def validate(config: Any) -> List[ReferenceIssue]:
        issues = list(original_validate(config))

        def context_of(item: Any) -> Optional[str]:
            return getattr(item, "source_context", None) or getattr(item, "source_attributes", {}).get("source_context")

        def scoped(items: List[Any], name: str, context: Optional[str]) -> Optional[Any]:
            return next((item for item in items if getattr(item, "name", None) == name and context_of(item) == context), None)

        for class_map in config.class_maps:
            context = context_of(class_map)
            for match in class_map.matches:
                if getattr(match, "match_type", None) != "class_map" or not getattr(match, "class_map_name", None):
                    continue
                target = scoped(config.class_maps, match.class_map_name, context)
                match.resolved = target is not None
                match.resolved_target_type = "class_map" if target is not None else None
                if target is None:
                    reason = f"Unresolved class map reference: {match.class_map_name}"
                    if reason not in match.review_reasons:
                        match.review_reasons.append(reason)
                    class_map.requires_manual_review = True
                    if class_map.migration_status != "PARSE_ERROR":
                        class_map.migration_status = "PARTIALLY_NORMALIZED"
                    issues.append(ReferenceIssue("class_map", class_map.name, match.class_map_name, False, "Unresolved class map reference", context, "class-map"))

        for policy in config.policy_maps:
            if getattr(policy, "policy_map_type", None) != "inspect":
                continue
            context = context_of(policy)
            for section in getattr(policy, "inspection_sections", []):
                if section.kind != "class" or not section.class_name:
                    continue
                target = scoped(config.class_maps, section.class_name, context)
                if target is None:
                    policy.requires_manual_review = True
                    if policy.migration_status != "PARSE_ERROR":
                        policy.migration_status = "PARTIALLY_NORMALIZED"
                    issues.append(ReferenceIssue("class_map", policy.name, section.class_name, False, "Unresolved inspection class map reference", context, section.class_name))

        if config.dns_settings.default_server_group:
            name = config.dns_settings.default_server_group
            resolved = any(group.name == name and context_of(group) is None for group in config.dns_server_groups)
            issues.append(ReferenceIssue("dns_server_group", config.dns_settings.name, name, resolved, "resolved" if resolved else "Unresolved DNS server group reference", None, "dns-group"))

        for tunnel in config.tunnel_groups:
            if not tunnel.trustpoint:
                continue
            context = context_of(tunnel)
            resolved = any(record.name == tunnel.trustpoint and record.source_context == context for record in config.trustpoint_records)
            if not resolved:
                issues.append(ReferenceIssue("trustpoint", tunnel.name, tunnel.trustpoint, False, "Unresolved context-local trustpoint reference", context, "vpn"))

        admin_name = config.multi_context_system.admin_context_name
        if admin_name:
            resolved = any(context.name == admin_name for context in config.contexts)
            issues.append(ReferenceIssue("context", "admin-context", admin_name, resolved, "resolved" if resolved else "Unresolved admin context reference", None, "system"))

        system_interfaces = {
            item.name for item in config.interfaces if context_of(item) is None
        }
        system_interfaces.update(
            item.nameif for item in config.interfaces if context_of(item) is None and getattr(item, "nameif", None)
        )
        for context in config.contexts:
            for entry in getattr(context, "allocated_interface_entries", []):
                if entry.range_expression:
                    entry.resolved = None
                    entry.review_reasons.append("Interface range resolution requires platform-specific expansion")
                    continue
                entry.resolved = entry.physical_interface in system_interfaces
                if not entry.resolved:
                    entry.review_reasons.append(f"Unresolved allocated interface: {entry.physical_interface}")
                    context.requires_manual_review = True
                    issues.append(ReferenceIssue("interface", context.name, entry.physical_interface, False, "Unresolved allocated interface reference", None, "allocate-interface"))
        return issues
    return validate


def _parse_raw_phase(self: Any) -> Any:
    config = _ORIGINALS["parse_raw"](self)
    _postprocess_dns(self)
    _postprocess_interface_dhcprelay(self)
    _postprocess_trustpoints(self)
    _postprocess_contexts(self)
    _postprocess_failover_groups(self)
    _postprocess_no_service_policies(self)
    _postprocess_http_server(self)
    # Enrichment above adds references that do not exist during the first
    # validation pass in the legacy parser.
    import fwmigrate.parsers.cisco_asa.parser as parser_module
    parser_module.apply_reference_issues(self.config, parser_module.validate_references(self.config))
    return self.config


def apply_phase_10_17_patches(parser_cls: Any) -> None:
    """Install the Phase 10-17 compatibility extension on CiscoASAParser.

    The ASA parser predates the current typed extraction model and is a large
    module used by many tests.  Keeping these additions isolated lets the new
    grammars be reviewed independently while preserving the public parser API.
    """
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True

    import fwmigrate.parsers.cisco_asa.parser as parser_module

    _ORIGINALS["parse_raw"] = parser_cls.parse_raw
    _ORIGINALS["management"] = parser_cls._parse_management_command
    _ORIGINALS["validate_references"] = parser_module.validate_references

    # Replace parser-module model symbols so the existing parser creates the
    # extended Pydantic models in all legacy code paths as well.
    parser_module.CiscoASAConfig = CiscoASAConfigPhase10_17
    parser_module.CiscoASAContext = CiscoASAContextPhase16
    parser_module.CiscoClassMap = CiscoClassMapPhase10
    parser_module.CiscoClassMapMatch = CiscoClassMapMatchPhase10
    parser_module.CiscoPolicyMap = CiscoPolicyMapPhase10
    parser_module.CiscoPolicyMapClass = CiscoPolicyMapClassPhase10
    parser_module.CiscoMPFConnectionAction = CiscoMPFConnectionActionPhase11
    parser_module.CiscoMPFPoliceAction = CiscoMPFPoliceActionPhase11
    parser_module.CiscoTCPMap = CiscoTCPMapPhase11
    parser_module.CiscoServicePolicy = CiscoServicePolicyPhase10
    parser_module.CiscoConnectionControl = CiscoConnectionControlPhase11
    parser_module.CiscoDNSServerGroup = CiscoDNSServerGroupPhase12
    parser_module.CiscoManagementAccessRule = CiscoManagementAccessRulePhase14
    parser_module.CiscoNTPServer = CiscoNTPServerPhase14
    parser_module.CiscoFailoverGroup = CiscoFailoverGroupPhase15

    parser_module.validate_references = _extend_reference_validation(parser_module.validate_references)

    parser_cls._build_context_ownership = staticmethod(_build_context_ownership_phase)
    parser_cls._parse_class_map_block = _parse_class_map_block_phase
    parser_cls._parse_policy_map_block = _parse_policy_map_block_phase
    parser_cls._parse_mpf_action = _parse_mpf_action_phase
    parser_cls._parse_connection_action = _parse_connection_action_phase
    parser_cls._parse_police_action = _parse_police_action_phase
    parser_cls._parse_tcp_map_block = _parse_tcp_map_block_phase
    parser_cls._parse_service_policy_line = _parse_service_policy_line_phase
    parser_cls._parse_threat_detection = _parse_threat_detection_phase
    parser_cls._parse_dhcpd_command = _parse_dhcpd_command_phase
    parser_cls._parse_management_command = _parse_management_command_phase
    parser_cls.parse_raw = _parse_raw_phase
