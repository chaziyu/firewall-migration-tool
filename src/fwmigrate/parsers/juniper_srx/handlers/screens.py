from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperScreenOption, JuniperScreenProfile
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_screens_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 4 or t[1:3] != ["security", "screen"]:
        return False
    profile = context.screens.setdefault(t[3], JuniperScreenProfile(name=t[3]))
    cmd.consumed, cmd.handler = True, "screens"
    if len(t) == 4:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    path = t[4:]
    profile.options.append(JuniperScreenOption(path=path, values=[]))
    profile.source_attributes["_".join(sanitize_tokens(path))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
