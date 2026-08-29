"""Handler for Junos system and version configuration hierarchy."""

from __future__ import annotations

from typing import Sequence

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes
from fwmigrate.parsers.juniper_srx.model import JuniperSRXConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_system_command(cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
    """
    Handle 'set version ...' and 'set system ...' hierarchy commands.
    Returns True if handled.
    """
    toks = cmd.tokens
    if len(toks) < 2:
        return False

    first = toks[1].lower()

    if first == "version":
        if len(toks) >= 3:
            config.version = toks[2]
            cmd.consumed = True
            cmd.handler = "system"
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

    if first == "system":
        cmd.consumed = True
        cmd.handler = "system"

        if len(toks) >= 3:
            sub = toks[2].lower()
            if sub == "host-name" and len(toks) >= 4:
                config.hostname = toks[3]
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "time-zone" and len(toks) >= 4:
                config.time_zone = toks[3]
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "name-server" and len(toks) >= 4:
                ns_list = extract_value_list(toks[3:])
                for ns in ns_list:
                    if ns not in config.name_servers:
                        config.name_servers.append(ns)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True

        # Other system attributes (e.g. login, ntp, syslog) -> EXTRACT_ONLY
        root_ctx = config.get_context("root")
        key = " ".join(toks[2:]) if len(toks) > 2 else "system"
        root_ctx.source_attributes[f"system_{key.replace(' ', '_')}"] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False
