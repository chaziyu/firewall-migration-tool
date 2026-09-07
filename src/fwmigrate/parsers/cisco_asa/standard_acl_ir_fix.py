from __future__ import annotations

from typing import Any, List

from fwmigrate.core.constants import IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4
from fwmigrate.ir.core import IRAddress
from fwmigrate.ir.enums import AddressType


_PATCHED = False


def _destination_reference(ir: Any, rule: Any) -> List[str]:
    endpoint = rule.destination_endpoint
    if endpoint is None or not endpoint.valid or endpoint.value is None:
        return []

    if endpoint.type == "any":
        if endpoint.value == "any6":
            return []
        # ASA standard ACLs are IPv4-only even when the source text uses `any`.
        return [IR_KEYWORD_ANY_IPV4]

    if endpoint.type in {"object", "object-group"}:
        return [endpoint.value]

    if endpoint.type in {"inline", "host"}:
        value = endpoint.value
        if endpoint.type == "host" and "/" not in value:
            value = f"{value}/32"
        from fwmigrate.parsers.cisco_asa.parser import _safe_name

        prefix = "asa_inline_host" if endpoint.type == "host" or "/32" in value else "asa_inline_net"
        name = _safe_name(prefix, value)
        if not any(item.name == name and item.source_context == rule.source_context for item in ir.addresses):
            ir.addresses.append(IRAddress(
                name=name,
                source_context=rule.source_context,
                type=AddressType.HOST if prefix.endswith("host") else AddressType.NETWORK,
                subnet=value,
                raw_value=endpoint.raw,
                address_family="ipv4",
                is_ipv6=False,
            ))
        return [name]

    return []


def apply_standard_acl_ir_fix(parser_cls: Any) -> None:
    """Project corrected ASA standard-ACL semantics into canonical IR."""
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True

    original = parser_cls.transform_to_ir

    def transform(self: Any):
        ir = original(self)
        standard_rules = {
            (rule.source_context, rule.id): rule
            for rule in self.config.access_rules
            if rule.acl_type == "standard"
        }

        for policy in ir.policies:
            rule = standard_rules.get((policy.source_context, policy.source_rule_id))
            if rule is None:
                continue

            destination = _destination_reference(ir, rule)
            policy.source = [IR_KEYWORD_ANY]
            policy.destination = destination
            policy.service = [IR_KEYWORD_ANY]
            policy.source_address_references = list(policy.source)
            policy.destination_address_references = list(destination)
            policy.source_service_references = list(policy.service)
            policy.requires_manual_review = True
            if rule.migration_status == "PARSE_ERROR" or not destination:
                policy.migration_status = "PARSE_ERROR"
            else:
                policy.migration_status = "PARTIALLY_NORMALIZED"

            obsolete = {
                "Standard ACL has no extended protocol, destination, or service operands",
                "Policy has unresolved address or service semantics",
            }
            policy.review_reasons = [reason for reason in policy.review_reasons if reason not in obsolete]
            reason = "ASA standard ACL is destination-only IPv4; target placement semantics require review"
            if reason not in policy.review_reasons:
                policy.review_reasons.append(reason)

        return ir

    parser_cls.transform_to_ir = transform
