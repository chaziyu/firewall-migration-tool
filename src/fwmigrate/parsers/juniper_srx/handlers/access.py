"""Source-only extraction for Junos access profiles and authentication."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperSourceHierarchyItem
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_access_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "access":
        return False
    name = toks[3] if len(toks) > 3 and toks[2].lower() == "profile" else toks[2]
    item = context.access_profiles.setdefault(name, JuniperSourceHierarchyItem(name=name))
    key_start = 4 if len(toks) > 3 and toks[2].lower() == "profile" else 3
    item.settings["_".join(sanitize_tokens(toks[key_start:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.consumed, cmd.handler = True, "access"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
