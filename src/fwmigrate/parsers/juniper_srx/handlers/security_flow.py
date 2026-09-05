from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_security_flow_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    if len(cmd.tokens) < 3 or cmd.tokens[1:3] != ["security", "flow"]:
        return False
    toks = cmd.tokens[3:]
    key = "_".join(sanitize_tokens(toks)) or "flow"
    context.security_flow.settings[key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.consumed, cmd.handler = True, "security_flow"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
