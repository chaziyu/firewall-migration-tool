"""Structured, secret-safe extraction for Junos IDP policies."""
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperIDPPolicy, JuniperIDPRule
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list

def handle_idp_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 4 or [v.lower() for v in t[1:3]] != ["security", "idp"]:
        return False
    if len(t) < 5 or t[3].lower() not in {"idp-policy", "policy"}:
        return _store(context.source_attributes, t[3:], cmd)
    policy = context.idp_policies.setdefault(t[4], JuniperIDPPolicy(name=t[4]))
    rest = t[5:]
    if not rest:
        return _done(cmd)
    if rest[0].lower() in {"rulebase-ips", "rulebase"} and len(rest) >= 3 and rest[1].lower() == "rule":
        base, name = rest[0], rest[2]
        rule = next((r for r in policy.rulebase.setdefault(base, []) if r.name == name), None)
        if rule is None:
            rule = JuniperIDPRule(name=name); policy.rulebase[base].append(rule)
        body = rest[3:]
        if body:
            key, vals = body[0].lower(), extract_value_list(body[1:])
            if key in {"match", "signature", "attack", "attacks", "application", "protocol"}:
                if key == "match" and vals:
                    key, vals = vals[0].lower(), vals[1:]
                rule.match.setdefault(key, []).extend(v for v in sanitize_tokens(vals) if v not in rule.match.setdefault(key, []))
            elif key in {"except", "exception", "exceptions"}:
                rule.exceptions.extend(v for v in sanitize_tokens(vals) if v not in rule.exceptions)
            elif key in {"action", "severity"}:
                target = rule.severity if key == "severity" else None
                if target is not None: target.extend(v for v in sanitize_tokens(vals) if v not in target)
                elif vals: rule.action = sanitize_tokens(vals)[0]
            else: rule.source_attributes.update(sanitize_source_attributes({"_".join(sanitize_tokens(body)): {"raw": cmd.raw_sanitized}}))
        return _done(cmd)
    return _store(policy.source_attributes, rest, cmd)

def _done(cmd):
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "idp", ExtractionStatus.EXTRACT_ONLY; return True
def _store(target, path, cmd):
    target["_".join(sanitize_tokens(path))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    return _done(cmd)
