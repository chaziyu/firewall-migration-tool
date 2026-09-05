"""Handler for Junos chassis-cluster source inventory."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_chassis_cluster_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "chassis" or toks[2].lower() != "cluster":
        return False
    key = "_".join(sanitize_tokens(toks[3:])) or "cluster"
    context.source_attributes.setdefault("chassis_cluster", {}).setdefault(key, []).append(
        sanitize_source_attributes({"raw": cmd.raw_sanitized, "tokens": toks[3:]})
    )
    cmd.consumed = True
    cmd.handler = "chassis_cluster"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
