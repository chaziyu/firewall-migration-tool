"""Source inventory handler for platform-specific chassis hierarchies."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperChassisItem, JuniperContextConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_chassis_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 2 or toks[1].lower() not in {"chassis", "virtual-chassis"}:
        return False
    path = toks[1:]
    context.chassis.append(JuniperChassisItem(
        hierarchy=" ".join(sanitize_tokens(path)),
        values=sanitize_tokens(path[1:]),
        source_attributes=sanitize_source_attributes({"raw": cmd.raw_sanitized}),
    ))
    cmd.consumed = True
    cmd.handler = "chassis"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    cmd.requires_manual_review = True
    return True
