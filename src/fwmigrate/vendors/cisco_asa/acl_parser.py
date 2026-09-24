from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from fwmigrate.extraction.sanitize import sanitize_raw_text
from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLBinding, CiscoACLEndpoint, CiscoAccessRule
from fwmigrate.vendors.cisco_asa.model.service import CiscoPortSpec
from fwmigrate.vendors.cisco_asa.net_utils import normalize_ipv4_network


PORT_OPERATORS = {"eq", "neq", "lt", "gt", "range", "object", "object-group"}
TRANSPORT_PROTOCOLS = {"tcp", "udp", "sctp"}
KNOWN_PROTOCOLS = {
    "ip", "tcp", "udp", "sctp", "icmp", "icmp6", "icmpv6",
    "gre", "esp", "ah", "eigrp", "ospf", "igmp", "ipinip", "pim",
}


def parse_port_spec(tokens: List[str], index: int) -> Tuple[Optional[CiscoPortSpec], int]:
    if index >= len(tokens) or tokens[index].lower() not in PORT_OPERATORS:
        return None, index
    start = index
    operator = tokens[index].lower()
    index += 1
    needed = 2 if operator == "range" else 1
    if index + needed > len(tokens):
        return CiscoPortSpec(operator=operator, raw=" ".join(tokens[start:])), len(tokens)
    values = tokens[index:index + needed]
    index += needed
    object_name = values[0] if operator in {"object", "object-group"} else None
    return CiscoPortSpec(
        operator=operator,
        values=values,
        object_name=object_name,
        raw=" ".join(tokens[start:index]),
    ), index


def parse_endpoint(tokens: List[str], index: int) -> Tuple[CiscoACLEndpoint, int]:
    if index >= len(tokens):
        return CiscoACLEndpoint(type="missing", raw="", valid=False), index
    token = tokens[index]
    lower = token.lower()
    if lower in {"any", "any4", "any6"}:
        family = "ipv6" if lower == "any6" else "ipv4" if lower == "any4" else None
        return CiscoACLEndpoint(type="any", value=lower, address_family=family, raw=token), index + 1
    if lower in {"host", "object", "object-group", "interface", "object-group-network-service"}:
        if index + 1 >= len(tokens):
            return CiscoACLEndpoint(type=lower, raw=token, valid=False), index + 1
        value = tokens[index + 1]
        family = None
        if lower == "host":
            try:
                family = "ipv6" if ipaddress.ip_address(value).version == 6 else "ipv4"
            except ValueError:
                return CiscoACLEndpoint(type=lower, value=value, raw=f"{token} {value}", valid=False), index + 2
        return CiscoACLEndpoint(type=lower, value=value, address_family=family, raw=f"{token} {value}"), index + 2
    if ":" in token:
        try:
            value = str(ipaddress.ip_network(token, strict=False))
            return CiscoACLEndpoint(type="inline", value=value, address_family="ipv6", raw=token), index + 1
        except ValueError:
            return CiscoACLEndpoint(type="inline", value=token, address_family="ipv6", raw=token, valid=False), index + 1
    if index + 1 < len(tokens):
        normalized = normalize_ipv4_network(token, tokens[index + 1])
        if normalized is not None:
            return CiscoACLEndpoint(type="inline", value=normalized, address_family="ipv4", raw=f"{token} {tokens[index + 1]}"), index + 2
        if re.fullmatch(r"\d+(?:\.\d+){3}", token):
            return CiscoACLEndpoint(type="inline", value=None, address_family="ipv4", raw=f"{token} {tokens[index + 1]}", valid=False), index + 2
    return CiscoACLEndpoint(type="unknown", value=token, raw=token, valid=False), index + 1


def parse_acl_binding(line: str, line_number: int) -> Optional[CiscoACLBinding]:
    tokens = line.split()
    if len(tokens) < 3 or tokens[0].lower() != "access-group":
        return None
    acl_name = tokens[1]
    lower = [item.lower() for item in tokens]
    direction = lower[2] if lower[2] in {"in", "out", "global"} else None
    interface = None
    review_reasons: List[str] = []
    if direction == "global":
        if len(tokens) > 3:
            review_reasons.append("Unexpected global access-group tokens were preserved")
    elif direction in {"in", "out"} and len(tokens) >= 5 and lower[3] == "interface":
        interface = tokens[4]
    else:
        return None
    modifiers = {"control-plane", "per-user-override"}
    unknown_tokens = [token for token in tokens[3:] if token.lower() not in modifiers and token.lower() != "interface" and token != interface]
    if unknown_tokens:
        review_reasons.append("Unmodeled access-group tokens were preserved")
    explicit_fields = {"acl_name"}
    if direction:
        explicit_fields.add("direction")
    if interface:
        explicit_fields.add("interface")
    if "control-plane" in lower:
        explicit_fields.add("control_plane")
    if "per-user-override" in lower:
        explicit_fields.add("per_user_override")
    return CiscoACLBinding(
        acl_name=acl_name,
        interface=interface,
        direction=direction,
        control_plane="control-plane" in lower,
        per_user_override="per-user-override" in lower,
        raw_line=line,
        line_number=line_number,
        source_attributes={"raw_tokens": tokens[2:], "binding_scope": "global" if direction == "global" else "interface"},
        extraction_status="PARTIAL" if review_reasons else "EXTRACTED",
        requires_manual_review=bool(review_reasons),
        review_reasons=review_reasons,
        explicit_fields=explicit_fields,
    )


def parse_acl_line(
    line: str,
    line_number: int,
    remarks: Dict[str, List[str]],
) -> Tuple[Optional[CiscoAccessRule], Optional[str]]:
    tokens = line.split()
    if len(tokens) < 3 or tokens[0].lower() != "access-list":
        return None, None
    acl_name = tokens[1]
    index = 2
    sequence = None
    if index < len(tokens) and tokens[index].lower() == "line":
        if index + 1 >= len(tokens) or not tokens[index + 1].isdigit():
            return None, "Malformed access-list line sequence"
        sequence = int(tokens[index + 1])
        index += 2
    if index < len(tokens) and tokens[index].lower() == "remark":
        return None, None
    if index >= len(tokens) or tokens[index].lower() not in {"standard", "extended"}:
        return None, f"Unsupported ACL type for {acl_name}"
    acl_type = tokens[index].lower()
    index += 1
    if index >= len(tokens) or tokens[index].lower() not in {"permit", "deny"}:
        return None, "Missing or unsupported ACL action"
    action = tokens[index].lower()
    index += 1

    protocol = None
    protocol_object = None
    identity_type = None
    identity_value = None
    source_sg_type = source_sg_value = None
    destination_sg_type = destination_sg_value = None
    source_port = destination_port = None
    destination = None
    source = None
    if acl_type == "standard":
        destination, index = parse_endpoint(tokens, index)
    else:
        if index >= len(tokens):
            return None, "Missing ACL protocol"
        protocol_token = tokens[index].lower()
        index += 1
        if protocol_token in {"object", "object-group"}:
            if index >= len(tokens):
                return None, "Missing ACL protocol object name"
            protocol_object = tokens[index]
            index += 1
            protocol = protocol_token
        elif protocol_token in KNOWN_PROTOCOLS or protocol_token.isdigit():
            protocol = "icmp6" if protocol_token == "icmpv6" else protocol_token
        else:
            protocol = protocol_token

        # Identity firewall selectors occur before address operands.
        if index < len(tokens) and tokens[index].lower() in {"user", "user-group", "object-group-user"}:
            identity_type = tokens[index].lower()
            if index + 1 >= len(tokens):
                return None, f"Missing {identity_type} selector value"
            identity_value = tokens[index + 1]
            index += 2

        def parse_security_group(position: int) -> Tuple[Optional[str], Optional[str], int]:
            if position >= len(tokens):
                return None, None, position
            selector = tokens[position].lower()
            if selector == "security-group":
                if position + 2 >= len(tokens) or tokens[position + 1].lower() not in {"name", "tag"}:
                    return "malformed", None, min(len(tokens), position + 1)
                return tokens[position + 1].lower(), tokens[position + 2], position + 3
            if selector == "object-group-security":
                if position + 1 >= len(tokens):
                    return "malformed", None, len(tokens)
                return "object-group", tokens[position + 1], position + 2
            return None, None, position

        source_sg_type, source_sg_value, index = parse_security_group(index)
        source, index = parse_endpoint(tokens, index)
        source_port_start = index
        if protocol in TRANSPORT_PROTOCOLS:
            source_port, index = parse_port_spec(tokens, index)
        destination_sg_type, destination_sg_value, index = parse_security_group(index)
        destination, index = parse_endpoint(tokens, index)
        if (
            protocol in TRANSPORT_PROTOCOLS
            and source_port is not None
            and source_port.operator in {"object", "object-group"}
            and not destination.valid
        ):
            # ``object``/``object-group`` can be either a port selector or an
            # address endpoint.  When the port interpretation leaves no valid
            # destination, retain the safer address interpretation.
            source_port = None
            destination_sg_type, destination_sg_value, index = parse_security_group(source_port_start)
            destination, index = parse_endpoint(tokens, index)
        if protocol in TRANSPORT_PROTOCOLS:
            destination_port, index = parse_port_spec(tokens, index)

    explicit_fields = {"acl_name", "acl_type", "action"}
    explicit_fields.update(
        name for name, value in (
            ("source_sequence", sequence), ("protocol", protocol), ("protocol_object", protocol_object),
            ("source_endpoint", source), ("source_port", source_port),
            ("destination_endpoint", destination), ("destination_port", destination_port),
            ("user", identity_value if identity_type == "user" else None),
            ("user_group", identity_value if identity_type in {"user-group", "object-group-user"} else None),
            ("source_security_group_type", source_sg_type), ("source_security_group_value", source_sg_value),
            ("destination_security_group_type", destination_sg_type),
            ("destination_security_group_value", destination_sg_value),
        ) if value is not None
    )
    rule = CiscoAccessRule(
        id=f"{acl_name}_{sequence if sequence is not None else line_number}",
        acl_name=acl_name,
        acl_type=acl_type,
        source_line_number=line_number,
        source_order=line_number,
        source_sequence=sequence,
        action=action,
        protocol=protocol,
        protocol_object=protocol_object,
        source_endpoint=source,
        source_port=source_port,
        destination_endpoint=destination,
        destination_port=destination_port,
        user=identity_value if identity_type == "user" else None,
        user_group=identity_value if identity_type in {"user-group", "object-group-user"} else None,
        source_security_group_type=source_sg_type,
        source_security_group_value=source_sg_value,
        destination_security_group_type=destination_sg_type,
        destination_security_group_value=destination_sg_value,
        remark=None,
        raw_line=line,
        extraction_status="EXTRACTED",
        explicit_fields=explicit_fields,
        source_attributes={
            "acl_type": acl_type,
            "raw_line": line,
            "source_line_number": line_number,
            "source_sequence": sequence,
        },
    )

    def mark(reason: str, status: str = "PARTIAL") -> None:
        rule.requires_manual_review = True
        if status == "PARSE_ERROR" or rule.extraction_status == "PARSE_ERROR":
            rule.extraction_status = "PARSE_ERROR"
        elif rule.extraction_status == "EXTRACTED":
            rule.extraction_status = status
        rule.review_reasons.append(reason)

    if identity_type:
        mark("Identity condition requires target review")
    if source_sg_type or destination_sg_type:
        mark("TrustSec security-group condition is source-specific", "PARSE_ERROR" if "malformed" in {source_sg_type, destination_sg_type} else "PARTIAL")
    if protocol is not None and protocol not in KNOWN_PROTOCOLS and not protocol.isdigit() and protocol not in {"object", "object-group"}:
        mark(f"Unknown protocol selector '{protocol}' was not converted to IP")
    endpoints = (source, destination)
    if any(endpoint is None or not endpoint.valid for endpoint in endpoints if endpoint is not None) or (acl_type == "standard" and destination is None):
        mark("One or more ACL endpoints could not be parsed safely", "PARSE_ERROR")
        rule.source_attributes["invalid_endpoint_values"] = [
            endpoint.raw for endpoint in endpoints if endpoint is not None and not endpoint.valid
        ]
    if acl_type == "standard" and destination is not None and (destination.address_family == "ipv6" or destination.value == "any6"):
        mark("ASA standard ACLs are IPv4-only", "PARSE_ERROR")
    if any(spec is not None and not spec.values for spec in (source_port, destination_port)):
        mark("ACL port expression is incomplete", "PARSE_ERROR")

    while index < len(tokens):
        token = tokens[index].lower()
        if token == "time-range":
            if index + 1 >= len(tokens):
                rule.raw_extra.setdefault("invalid_options", []).append(sanitize_raw_text(" ".join(tokens[index:])))
                mark("Missing time-range name", "PARSE_ERROR")
                index += 1
            else:
                rule.time_range = tokens[index + 1]
                rule.explicit_fields.add("time_range")
                index += 2
        elif token == "inactive":
            rule.inactive = True
            rule.explicit_fields.add("inactive")
            index += 1
        elif token == "log":
            start = index
            rule.log_enabled = True
            rule.explicit_fields.add("log_enabled")
            index += 1
            if index < len(tokens) and tokens[index].lower() == "disable":
                rule.log_enabled = False
                index += 1
            elif index < len(tokens) and tokens[index].lower() not in {"interval", "inactive", "time-range"}:
                rule.log_level = tokens[index]
                rule.explicit_fields.add("log_level")
                index += 1
            if index < len(tokens) and tokens[index].lower() == "interval":
                if index + 1 >= len(tokens) or not tokens[index + 1].isdigit():
                    rule.raw_extra.setdefault("invalid_options", []).append(sanitize_raw_text(" ".join(tokens[index:])))
                    mark("Malformed log interval", "PARSE_ERROR")
                    index += 1
                else:
                    rule.log_interval = int(tokens[index + 1])
                    rule.explicit_fields.add("log_interval")
                    index += 2
            rule.log_raw = " ".join(tokens[start:index])
        elif protocol in {"icmp", "icmp6"} and token == "object-group" and index + 1 < len(tokens):
            rule.icmp_object_group = tokens[index + 1]
            rule.explicit_fields.add("icmp_object_group")
            index += 2
        elif protocol in {"icmp", "icmp6"} and token == "object-group":
            rule.raw_extra.setdefault("invalid_options", []).append(sanitize_raw_text(" ".join(tokens[index:])))
            mark("Missing ICMP object-group name", "PARSE_ERROR")
            index += 1
        elif protocol in {"icmp", "icmp6"} and rule.icmp_type is None:
            rule.icmp_type = tokens[index]
            rule.explicit_fields.add("icmp_type")
            if index + 1 < len(tokens) and tokens[index + 1].isdigit():
                rule.icmp_code = int(tokens[index + 1])
                rule.explicit_fields.add("icmp_code")
                index += 2
            else:
                index += 1
        else:
            rule.raw_extra.setdefault("unknown_subcommands", []).append(sanitize_raw_text(" ".join(tokens[index:])))
            mark(f"Unmodeled ACL token '{tokens[index]}'")
            index = len(tokens)
    return rule, None

