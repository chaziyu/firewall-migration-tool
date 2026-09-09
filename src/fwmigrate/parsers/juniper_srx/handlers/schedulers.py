"""Handler for Junos schedulers configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperContextConfig, JuniperScheduler, JuniperProvenanceKind, JuniperSourceProvenance,
)
from fwmigrate.parsers.juniper_srx.provenance import record_member_candidate, record_scalar_candidate
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


_DAYS_OF_WEEK = {
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
}


def handle_schedulers_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set schedulers scheduler <name> ...' hierarchy commands.
    """
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "schedulers":
        return False

    cmd.consumed = True
    cmd.handler = "schedulers"

    if len(toks) >= 4 and toks[2].lower() == "scheduler":
        sched_name = toks[3]
        if sched_name not in context.schedulers:
            context.schedulers[sched_name] = JuniperScheduler(name=sched_name)
        sched = context.schedulers[sched_name]
        sched.provenance = JuniperSourceProvenance(
            kind=JuniperProvenanceKind.INHERITED_GROUP if cmd.source_group else JuniperProvenanceKind.LOCAL,
            context=context.context, group_name=cmd.source_group,
        )

        if len(toks) == 4:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        i = 4
        handled_any = False
        while i < len(toks):
            sub = toks[i].lower()
            if sub == "description" and i + 1 < len(toks):
                sched.description = toks[i + 1]
                record_scalar_candidate(sched.field_provenance, sched.field_candidate_history, "description", sched.description, cmd)
                i += 2
                handled_any = True
            elif sub == "start-date" and i + 1 < len(toks):
                sched.start_date = toks[i + 1]
                record_scalar_candidate(sched.field_provenance, sched.field_candidate_history, "start_date", sched.start_date, cmd)
                i += 2
                handled_any = True
            elif sub == "stop-date" and i + 1 < len(toks):
                sched.stop_date = toks[i + 1]
                record_scalar_candidate(sched.field_provenance, sched.field_candidate_history, "stop_date", sched.stop_date, cmd)
                i += 2
                handled_any = True
            elif sub == "daily" and i + 1 < len(toks):
                time_val = " ".join(toks[i + 1:])
                record_member_candidate(sched.member_candidate_history, "daily", time_val, cmd)
                if time_val not in sched.daily:
                    sched.daily.append(time_val)
                    sched.daily_windows.append({"values": toks[i + 1:]})
                handled_any = True
                break
            elif sub in _DAYS_OF_WEEK and i + 1 < len(toks):
                time_val = " ".join(toks[i + 1:])
                record_member_candidate(sched.member_candidate_history, f"weekday:{sub}", time_val, cmd)
                sched.weekdays[sub] = time_val
                if not any(window.get("values") == toks[i + 1:] for window in sched.weekday_windows.setdefault(sub, [])):
                    sched.weekday_windows[sub].append({"values": toks[i + 1:]})
                handled_any = True
                break
            else:
                safe_toks = sanitize_tokens(toks)
                sched.source_attributes["_".join(safe_toks[i:])] = sanitize_source_attributes(
                    {"raw": cmd.raw_sanitized}
                )
                cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
                return True

        if handled_any:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        safe_toks = sanitize_tokens(toks)
        sched.source_attributes["_".join(safe_toks[4:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False
