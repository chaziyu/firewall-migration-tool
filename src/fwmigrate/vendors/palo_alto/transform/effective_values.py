"""Documented PAN-OS behavior, kept separate from explicit XML state."""
from dataclasses import dataclass
import re

from ..source_model import pan_scope_identity


RULE_REFERENCE = "https://docs.paloaltonetworks.com/ngfw/help/11-1/policies/policies-security/building-blocks-in-a-security-policy-rule"
USER_REFERENCE = "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy/create-a-security-policy-rule"


@dataclass(frozen=True, slots=True)
class PANEffectiveValue:
    identity: tuple
    field: str
    value: str
    version: str
    reference: str
    origin: str = "PANOS_DEFAULT"


def rule_identity(rule):
    return (pan_scope_identity(rule.scope) if rule.scope else "unscoped", rule.source_path, rule.name, rule.source_order)


def derive_effective_values(config):
    version = config.source_version or ""
    if not re.fullmatch(r"11\.1(?:\.\d+)?(?:-h\d+)?", version):
        return ()
    if any(s.kind in {"device-group", "template", "template-stack"} or s.device_serial or s.device_group for s in config.scopes):
        return ()
    # Only documented local rule behavior is derived; disabled/negation/category remain unknown.
    defaults = {"rule_type": "universal", "log_start": "no", "log_end": "yes", "source_user": "any", "schedule": "always"}
    return tuple(PANEffectiveValue(rule_identity(rule), field, value, version,
                                  USER_REFERENCE if field == "source_user" else RULE_REFERENCE)
                 for rule in config.security_rules
                 if rule.scope and rule.scope.kind == "vsys" and rule.rulebase_position in {None, "local"}
                 for field, value in defaults.items() if getattr(rule, field) is None and field not in rule.explicit_fields)


def effective_value(derived, rule, field):
    return getattr(derived, "effective_value_index", {}).get((rule_identity(rule), field))
