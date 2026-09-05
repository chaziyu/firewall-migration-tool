"""Handler for Junos schedulers configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperScheduler
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

        if len(toks) == 4:
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

        i = 4
        handled_any = False
        while i < len(toks):
            sub = toks[i].lower()
            if sub == "description" and i + 1 < len(toks):
                sched.description = toks[i + 1]
                i += 2
                handled_any = True
            elif sub == "start-date" and i + 1 < len(toks):
                sched.start_date = toks[i + 1]
                i += 2
                handled_any = True
            elif sub == "stop-date" and i + 1 < len(toks):
                sched.stop_date = toks[i + 1]
                i += 2
                handled_any = True
            elif sub == "daily" and i + 1 < len(toks):
                time_val = " ".join(toks[i + 1:])
                sched.daily.append(time_val)
                sched.daily_windows.append({"values": toks[i + 1:]})
                handled_any = True
                break
            elif sub in _DAYS_OF_WEEK and i + 1 < len(toks):
                time_val = " ".join(toks[i + 1:])
                sched.weekdays[sub] = time_val
                sched.weekday_windows.setdefault(sub, []).append({"values": toks[i + 1:]})
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
