"""Preserve verified Junos link-monitor statements as source inventory."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_link_monitor_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    if len(cmd.tokens) < 2 or cmd.tokens[1].lower() != "link-monitor":
        return False
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "link-monitor", ExtractionStatus.EXTRACT_ONLY
    context.source_attributes.setdefault("link_monitor", []).append(
        sanitize_source_attributes({"path": sanitize_tokens(cmd.tokens[1:]), "raw": cmd.raw_sanitized})
    )
    return True
