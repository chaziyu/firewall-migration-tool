"""Source-only extraction for Junos UTM policy/profile composition."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperSourceHierarchyItem
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_utm_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "security" or toks[2].lower() != "utm":
        return False
    name = toks[3] if len(toks) > 3 else "__global__"
    item = context.utm_policies.setdefault(name, JuniperSourceHierarchyItem(name=name))
    item.settings["_".join(sanitize_tokens(toks[4:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.consumed, cmd.handler = True, "utm"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
