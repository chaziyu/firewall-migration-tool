"""Handler for Junos VLAN configuration hierarchy."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperVLAN
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_vlans_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "vlans":
        return False
    vlan = context.vlans.setdefault(toks[2], JuniperVLAN(name=toks[2]))
    cmd.consumed = True
    cmd.handler = "vlans"
    if len(toks) == 3:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    if len(toks) >= 5 and toks[3].lower() == "vlan-id":
        try:
            vlan.vlan_id = int(toks[4])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            cmd.parse_error = f"Invalid vlan-id: {toks[4]}"
        return True
    if len(toks) >= 5 and toks[3].lower() == "l3-interface":
        vlan.l3_interface = toks[4]
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    if len(toks) >= 5 and toks[3].lower() == "interface":
        vlan.members.append(toks[4])
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    key = "_".join(sanitize_tokens(toks[3:]))
    vlan.source_attributes[key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
