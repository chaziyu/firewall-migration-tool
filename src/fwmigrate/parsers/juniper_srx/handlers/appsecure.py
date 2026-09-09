"""Conservative source extraction for Junos AppSecure configuration."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import (
    JuniperAppSecureRule,
    JuniperAppSecureRuleSet,
    JuniperContextConfig,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_appsecure_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() not in {"services", "security"}:
        return False
    if toks[2].lower() not in {"application-identification", "application-identification-profile", "appid"}:
        return False

    rest = toks[3:]
    if rest and rest[0].lower() in {"rule-set", "ruleset"} and len(rest) >= 2:
        ruleset = context.appsecure_rule_sets.setdefault(
            rest[1], JuniperAppSecureRuleSet(name=rest[1])
        )
        tail = rest[2:]
        if tail and tail[0].lower() == "rule" and len(tail) >= 2:
            rule = next((r for r in ruleset.rules if r.name == tail[1]), None)
            if rule is None:
                rule = JuniperAppSecureRule(name=tail[1])
                ruleset.rules.append(rule)
            if len(tail) > 2:
                rule.settings.setdefault("_".join(sanitize_tokens(tail[2:])), []).append(
                    sanitize_source_attributes({"raw": cmd.raw_sanitized})
                )
        elif tail:
            ruleset.settings.setdefault("_".join(sanitize_tokens(tail)), []).append(
                sanitize_source_attributes({"raw": cmd.raw_sanitized})
            )
        ruleset.source_attributes.update(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
    elif rest:
        key = "_".join(sanitize_tokens(rest))
        context.source_attributes.setdefault(f"appsecure_{key}", []).append(
            sanitize_source_attributes({"raw": cmd.raw_sanitized})
        )

    cmd.consumed, cmd.handler = True, "appsecure"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
