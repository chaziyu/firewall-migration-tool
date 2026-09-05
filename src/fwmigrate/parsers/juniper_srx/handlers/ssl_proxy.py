"""Structured, secret-safe extraction for Junos SSL proxy profiles."""
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperSSLProxyProfile

def handle_ssl_proxy_command(cmd, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 4 or t[1].lower() != "services" or t[2].lower() not in {"ssl", "ssl-proxy"}:
        return False
    i = 3
    if i < len(t) and t[i].lower() == "proxy": i += 1
    if i < len(t) and t[i].lower() == "profile": i += 1
    if i >= len(t): return _done(cmd)
    name = t[i]; profile = context.ssl_proxy_profiles.setdefault(name, JuniperSSLProxyProfile(name=name)); rest = t[i + 1:]
    if rest and rest[0].lower() in {"certificate", "server-certificate", "root-ca", "trusted-ca"}:
        if len(rest) > 1 and rest[1] not in profile.references:
            profile.references.append(rest[1])
    elif rest and rest[0].lower() == "private-key":
        profile.settings["private_key_configured"] = True
    elif rest:
        profile.settings.setdefault("_".join(sanitize_tokens(rest)), []).append(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
    profile.source_attributes.update(sanitize_source_attributes({"raw": cmd.raw_sanitized})); return _done(cmd)
def _done(cmd):
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "ssl_proxy", ExtractionStatus.EXTRACT_ONLY; return True
