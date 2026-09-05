from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperCertificate, JuniperSRXConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_pki_command(cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
    if len(cmd.tokens) < 2 or cmd.tokens[1].lower() not in {"security", "access"}:
        return False
    toks = cmd.tokens[2:]
    if not toks or toks[0].lower() not in {"pki", "certificates", "certificate"}:
        return False
    rest = toks[1:]
    name = rest[1] if len(rest) > 1 and rest[0].lower() in {"local-certificate", "ca-profile", "certificate"} else (rest[0] if rest else "pki")
    if rest and rest[0].lower() == "ca-profile":
        config.pki.ca_profiles.setdefault(name, {})["_".join(sanitize_tokens(rest))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        cmd.consumed, cmd.handler = True, "pki"
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    item = config.pki.certificates.setdefault(name, JuniperCertificate(name=name))
    key = "_".join(sanitize_tokens(rest)) or "configured"
    item.source_attributes[key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    if "certificate-id" in [x.lower() for x in rest]:
        i = [x.lower() for x in rest].index("certificate-id")
        if i + 1 < len(rest): item.certificate_id = rest[i + 1]
    cmd.consumed, cmd.handler = True, "pki"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
