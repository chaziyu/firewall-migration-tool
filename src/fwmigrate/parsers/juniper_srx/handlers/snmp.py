from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperSRXConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_snmp_command(cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
    if len(cmd.tokens) < 2 or cmd.tokens[1].lower() != "snmp":
        return False
    toks = cmd.tokens[2:]
    if not toks:
        return False
    target = config.snmp
    if toks[0].lower() in {"community", "trap-group"} and len(toks) >= 2:
        name = f"community_{len(target.communities) + 1}" if toks[0].lower() == "community" else toks[1]
        store = target.communities if toks[0].lower() == "community" else target.trap_groups
        item = store.setdefault(name, {})
        if toks[0].lower() == "community":
            item["name"] = "[REDACTED]"
        key = "_".join(sanitize_tokens(toks[2:])) or "configured"
        item[key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    else:
        target.options["_".join(sanitize_tokens(toks))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.consumed, cmd.handler = True, "snmp"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
