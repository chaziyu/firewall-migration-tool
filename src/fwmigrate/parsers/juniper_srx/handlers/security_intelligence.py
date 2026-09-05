"""Structured extraction for security-intelligence feeds and profiles."""
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperSecurityIntelligenceFeed, JuniperSecurityIntelligenceProfile

def handle_security_intelligence_command(cmd, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 4 or [v.lower() for v in t[1:3]] != ["security", "intelligence"]: return False
    kind = t[3].lower(); i = 4
    if i >= len(t): return _done(cmd)
    name = t[i]; rest = t[i + 1:]
    if kind in {"feed", "feeds", "feed-server", "feed-servers"}:
        obj = context.security_intelligence_feeds.setdefault(name, JuniperSecurityIntelligenceFeed(name=name))
        target = obj.references if rest and rest[0].lower() in {"url", "feed", "external-feed", "server"} else None
    else:
        obj = context.security_intelligence_profiles.setdefault(name, JuniperSecurityIntelligenceProfile(name=name))
        target = obj.feeds if rest and rest[0].lower() in {"feed", "feeds", "external-feed"} else (obj.actions if rest and rest[0].lower() in {"action", "actions"} else None)
    if rest:
        vals = sanitize_tokens(rest[1:])
        if target is not None: target.extend(v for v in vals if v not in target)
        else: obj.settings.setdefault("_".join(sanitize_tokens(rest)), []).append(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
    obj.source_attributes.update(sanitize_source_attributes({"raw": cmd.raw_sanitized})); return _done(cmd)
def _done(cmd):
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "security_intelligence", ExtractionStatus.EXTRACT_ONLY; return True
