from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperPrefixList
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_policy_options_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 4 or t[1:3] != ["policy-options", "prefix-list"]:
        return False
    obj = context.prefix_lists.setdefault(t[3], JuniperPrefixList(name=t[3]))
    cmd.consumed, cmd.handler = True, "policy_options"
    if len(t) >= 5 and t[4].lower() == "prefix-list" and len(t) >= 6:
        obj.entries.extend(v for v in extract_value_list(t[5:]) if v not in obj.entries)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
    elif len(t) >= 5 and t[4].lower() in {"deactivate", "disable"}:
        obj.disabled = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
    else:
        obj.source_attributes["_".join(sanitize_tokens(t[4:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
