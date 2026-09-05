"""Handler for Junos applications and application-sets configuration hierarchy."""

from __future__ import annotations

from typing import Union

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperApplication,
    JuniperApplicationSet,
    JuniperApplicationTerm,
    JuniperContextConfig,
    JuniperProvenanceKind,
    JuniperSourceProvenance,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


# Junos symbolic ICMP type lookup table
JUNOS_ICMP_TYPE_MAP: dict[str, int] = {
    "echo-reply": 0,
    "unreachable": 3,
    "destination-unreachable": 3,
    "source-quench": 4,
    "redirect": 5,
    "alternate-host-address": 6,
    "echo-request": 8,
    "router-advertisement": 9,
    "router-solicitation": 10,
    "time-exceeded": 11,
    "parameter-problem": 12,
    "timestamp-request": 13,
    "timestamp-reply": 14,
    "info-request": 15,
    "info-reply": 16,
    "mask-request": 17,
    "mask-reply": 18,
    "traceroute": 30,
}

JUNOS_ICMP_CODE_MAP: dict[str, int] = {
    "network-unreachable": 0,
    "host-unreachable": 1,
    "protocol-unreachable": 2,
    "port-unreachable": 3,
    "fragmentation-needed": 4,
    "source-route-failed": 5,
    "destination-network-unknown": 6,
    "destination-host-unknown": 7,
    "source-host-isolated": 8,
    "network-prohibited": 9,
    "host-prohibited": 10,
    "network-unreachable-for-tos": 11,
    "host-unreachable-for-tos": 12,
    "communication-prohibited": 13,
    "host-precedence-violation": 14,
    "precedence-cutoff": 15,
    "ttl-zero-during-transit": 0,
    "ttl-zero-during-reassembly": 1,
}


def resolve_icmp_type(val: Union[str, int, None]) -> int | None:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    try:
        return int(val)
    except ValueError:
        return JUNOS_ICMP_TYPE_MAP.get(str(val).lower())


def resolve_icmp_code(val: Union[str, int, None]) -> int | None:
    if val is None:
        return None
    if isinstance(val, int):
        return val
    try:
        return int(val)
    except ValueError:
        return JUNOS_ICMP_CODE_MAP.get(str(val).lower())


def handle_applications_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set applications ...' hierarchy commands.
    """
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "applications":
        return False

    sub = toks[2].lower()
    cmd.consumed = True
    cmd.handler = "applications"

    if sub == "application-set" and len(toks) >= 4:
        set_name = toks[3]
        if set_name not in context.application_sets:
            context.application_sets[set_name] = JuniperApplicationSet(name=set_name)
        appset = context.application_sets[set_name]
        appset.provenance = JuniperSourceProvenance(
            kind=JuniperProvenanceKind.INHERITED_GROUP if cmd.source_group else JuniperProvenanceKind.LOCAL,
            context=context.context, group_name=cmd.source_group,
        )

        if len(toks) == 4:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        sub_key = toks[4].lower()
        if sub_key == "application" and len(toks) >= 6:
            members = extract_value_list(toks[5:])
            for m in members:
                if m not in appset.applications:
                    appset.applications.append(m)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True
        elif sub_key == "application-set" and len(toks) >= 6:
            appset.source_attributes["nested_application_set"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True
        elif sub_key == "description" and len(toks) >= 6:
            appset.description = toks[5]
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        safe_toks = sanitize_tokens(toks)
        appset.source_attributes["_".join(safe_toks[4:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    if sub == "application" and len(toks) >= 4:
        app_name = toks[3]
        if app_name not in context.applications:
            context.applications[app_name] = JuniperApplication(name=app_name)
        app = context.applications[app_name]
        app.provenance = JuniperSourceProvenance(
            kind=JuniperProvenanceKind.INHERITED_GROUP if cmd.source_group else JuniperProvenanceKind.LOCAL,
            context=context.context, group_name=cmd.source_group,
        )

        if len(toks) == 4:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        # Check if term-based: set applications application <app> term <term> ...
        if toks[4].lower() == "term" and len(toks) >= 6:
            term_name = toks[5]
            term = _get_or_create_term(app, term_name)
            if len(toks) == 6:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_term_settings(cmd, toks[6:], term, app)
        else:
            # Default term
            term = _get_or_create_term(app, "__default__")
            return _parse_term_settings(cmd, toks[4:], term, app)

    return False


def _get_or_create_term(app: JuniperApplication, term_name: str) -> JuniperApplicationTerm:
    for t in app.terms:
        if t.name == term_name:
            return t
    new_t = JuniperApplicationTerm(name=term_name)
    app.terms.append(new_t)
    return new_t


def _parse_term_settings(
    cmd: JunosCommand,
    toks: list[str],
    term: JuniperApplicationTerm,
    app: JuniperApplication,
) -> bool:
    if not toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    i = 0
    handled_any = False
    is_partially_norm = False

    while i < len(toks):
        key = toks[i].lower()
        if key == "description" and i + 1 < len(toks):
            app.description = toks[i + 1]
            i += 2
            handled_any = True
        elif key == "protocol" and i + 1 < len(toks):
            proto_val = toks[i + 1]
            try:
                term.protocol_number = int(proto_val)
                term.protocol = proto_val
            except ValueError:
                term.protocol = proto_val
            i += 2
            handled_any = True
        elif key == "destination-port" and i + 1 < len(toks):
            # Extract port values until next known keyword or end
            ports = []
            i += 1
            if i < len(toks) and toks[i] == "[":
                # Bracket list
                i += 1
                while i < len(toks) and toks[i] != "]":
                    ports.append(toks[i])
                    i += 1
                if i < len(toks) and toks[i] == "]":
                    i += 1
            elif i < len(toks):
                ports.append(toks[i])
                i += 1
            for p in ports:
                if p not in term.destination_ports:
                    term.destination_ports.append(p)
            handled_any = True
        elif key == "source-port" and i + 1 < len(toks):
            ports = []
            i += 1
            if i < len(toks) and toks[i] == "[":
                i += 1
                while i < len(toks) and toks[i] != "]":
                    ports.append(toks[i])
                    i += 1
                if i < len(toks) and toks[i] == "]":
                    i += 1
            elif i < len(toks):
                ports.append(toks[i])
                i += 1
            for p in ports:
                if p not in term.source_ports:
                    term.source_ports.append(p)
            handled_any = True
        elif key == "icmp-type" and i + 1 < len(toks):
            term.icmp_type = toks[i + 1]
            i += 2
            handled_any = True
        elif key == "icmp-code" and i + 1 < len(toks):
            term.icmp_code = toks[i + 1]
            i += 2
            handled_any = True
        elif key == "application-protocol" and i + 1 < len(toks):
            term.application_protocol = toks[i + 1]
            i += 2
            handled_any = True
            is_partially_norm = True
        elif key == "inactivity-timeout" and i + 1 < len(toks):
            term.inactivity_timeout = toks[i + 1]
            i += 2
            handled_any = True
        else:
            safe_toks = sanitize_tokens(toks)
            term.source_attributes["_".join(safe_toks[i:])] = sanitize_source_attributes(
                {"raw": cmd.raw_sanitized}
            )
            cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
            return True

    if handled_any:
        cmd.extraction_status = (
            ExtractionStatus.PARTIALLY_NORMALIZED
            if is_partially_norm
            else ExtractionStatus.NORMALIZED
        )
        return True
    return False
