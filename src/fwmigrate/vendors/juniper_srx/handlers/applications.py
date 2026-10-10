"""Handler for Junos applications and application-sets configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.vendors.juniper_srx.model import (
    JuniperApplication,
    JuniperApplicationSet,
    JuniperApplicationSettings,
    JuniperApplicationTerm,
    JuniperContextConfig,
    JuniperProvenanceKind,
    JuniperSourceProvenance,
)
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand, extract_value_list
from fwmigrate.vendors.juniper_srx.provenance import record_scalar_candidate, record_list_candidate


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
            cmd.extraction_status = ExtractionStatus.EXTRACTED
            return True

        sub_key = toks[4].lower()
        if sub_key == "application" and len(toks) >= 6:
            members = extract_value_list(toks[5:])
            for m in members:
                if m not in appset.applications:
                    appset.applications.append(m)
                record_list_candidate(appset.member_candidate_history, "application", m, cmd)
            cmd.extraction_status = ExtractionStatus.EXTRACTED
            return True
        elif sub_key == "application-set" and len(toks) >= 6:
            # Canonical IR service groups already allow member references by name.
            # Preserve nested application-set references in the same ordered
            # membership list, while retaining explicit source evidence so
            # downstream validation can distinguish nested groups from apps.
            members = extract_value_list(toks[5:])
            nested = appset.source_attributes.setdefault("nested_application_sets", [])
            for m in members:
                if m not in appset.applications:
                    appset.applications.append(m)
                if m not in nested:
                    nested.append(m)
                record_list_candidate(appset.member_candidate_history, "application", m, cmd)
            cmd.extraction_status = ExtractionStatus.EXTRACTED
            return True
        elif sub_key == "description" and len(toks) >= 6:
            appset.description = toks[5]
            record_scalar_candidate(appset.field_provenance, appset.field_candidate_history, "description", appset.description, cmd)
            cmd.extraction_status = ExtractionStatus.EXTRACTED
            return True

        safe_toks = sanitize_tokens(toks)
        appset.source_attributes["_".join(safe_toks[4:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.SOURCE_ONLY
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
            cmd.extraction_status = ExtractionStatus.EXTRACTED
            return True

        # Check if term-based: set applications application <app> term <term> ...
        if toks[4].lower() == "term" and len(toks) >= 6:
            term_name = toks[5]
            term = _get_or_create_term(app, term_name)
            if len(toks) == 6:
                cmd.extraction_status = ExtractionStatus.EXTRACTED
                return True
            return _parse_term_settings(cmd, toks[6:], term, app)
        else:
            # Junos permits application properties directly on the application.
            # Preserve that source structure rather than fabricating a term.
            return _parse_term_settings(cmd, toks[4:], app.top_level, app)

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
    term: JuniperApplicationSettings,
    app: JuniperApplication,
) -> bool:
    if not toks:
        cmd.extraction_status = ExtractionStatus.EXTRACTED
        return True

    i = 0
    handled_any = False
    is_partially_norm = False

    while i < len(toks):
        key = toks[i].lower()
        if key == "description" and i + 1 < len(toks):
            app.description = toks[i + 1]
            record_scalar_candidate(app.field_provenance, app.field_candidate_history, "description", app.description, cmd)
            i += 2
            handled_any = True
        elif key == "protocol" and i + 1 < len(toks):
            proto_val = toks[i + 1]
            try:
                term.protocol_number = int(proto_val)
                term.protocol = proto_val
            except ValueError:
                term.protocol = proto_val
            record_scalar_candidate(term.field_provenance, term.field_candidate_history, "protocol", term.protocol, cmd)
            i += 2
            handled_any = True
        elif key == "destination-port" and i + 1 < len(toks):
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
            cmd.extraction_status = ExtractionStatus.SOURCE_ONLY
            return True

    if handled_any:
        cmd.extraction_status = (
            ExtractionStatus.PARTIAL
            if is_partially_norm
            else ExtractionStatus.EXTRACTED
        )
        cmd.requires_manual_review = is_partially_norm
        return True
    return False
