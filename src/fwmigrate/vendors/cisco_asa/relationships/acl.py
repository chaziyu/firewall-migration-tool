"""ASA ACL rules and access-group bindings remain separate source facts."""

from dataclasses import dataclass
from typing import Any

from .references import ASAReferenceIndex


@dataclass(frozen=True, slots=True)
class ASAACLBindingRelationship:
    source_context: str | None
    acl_name: str
    binding: Any
    rules: tuple[Any, ...]
    scope: str
    direction: str | None
    interface: str | None
    resolved_acl: Any = None
    resolved_interface: Any = None
    issues: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAACLRuleRelationship:
    rule: Any
    references: tuple[tuple[str, Any], ...] = ()
    issues: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAACLRelationships:
    bindings: tuple[ASAACLBindingRelationship, ...] = ()
    issues: tuple[Any, ...] = ()
    rules: tuple[ASAACLRuleRelationship, ...] = ()


def build_acl_relationships(config: Any, references: ASAReferenceIndex) -> ASAACLRelationships:
    from .references import ASAReferenceIssue, ASAReferenceKind, ASAReferenceStatus
    rows = []
    issues = []
    for binding in config.acl_bindings:
        context = getattr(binding, "source_context", None)
        acl = references.resolve(context, ASAReferenceKind.ACL, binding.acl_name)
        local = []
        if acl.status is not ASAReferenceStatus.RESOLVED:
            local.append(ASAReferenceIssue(context, ASAReferenceKind.ACL, "access-group", binding.acl_name, acl.status, "Unresolved or ambiguous ACL binding", "access-group"))
        interface = references.resolve(context, ASAReferenceKind.INTERFACE, binding.interface) if binding.interface else None
        if interface and interface.status is not ASAReferenceStatus.RESOLVED:
            local.append(ASAReferenceIssue(context, ASAReferenceKind.INTERFACE, "access-group", binding.interface, interface.status, "Unresolved or ambiguous access-group interface", "access-group"))
        rules = tuple(rule for rule in config.access_rules if rule.acl_name == binding.acl_name and getattr(rule, "source_context", None) == context)
        rows.append(ASAACLBindingRelationship(context, binding.acl_name, binding, rules, "interface" if binding.interface else "global", binding.direction, binding.interface, acl.target, interface.target if interface else None, tuple(local)))
        issues.extend(local)
    rule_rows = []
    for rule in config.access_rules:
        context = getattr(rule, "source_context", None)
        local = []
        targets = []

        def resolve(kind, name, field):
            if not name:
                return
            result = references.resolve(context, kind, str(name))
            if result.status is ASAReferenceStatus.RESOLVED:
                targets.append((field, result.target))
            else:
                local.append(ASAReferenceIssue(context, kind, getattr(rule, "id", rule.acl_name), str(name),
                                               result.status, f"Unresolved ACL {field} reference", field))

        protocol_object = getattr(rule, "protocol_object", None)
        selector_type = getattr(rule, "protocol_reference_type", None)
        if protocol_object and selector_type == "object":
            resolve(ASAReferenceKind.SERVICE_OBJECT, protocol_object, "protocol")
        elif protocol_object and selector_type == "object-group":
            result = references.resolve_one_of(context, protocol_object,
                                               (ASAReferenceKind.SERVICE_GROUP, ASAReferenceKind.PROTOCOL_GROUP))
            if result.status is ASAReferenceStatus.RESOLVED:
                targets.append(("protocol", result.target))
            else:
                local.append(ASAReferenceIssue(context, result.reference_kind, getattr(rule, "id", rule.acl_name),
                                               protocol_object, result.status,
                                               "Unresolved or ambiguous ACL protocol object-group reference", "protocol"))
        elif protocol_object:
            resolve(ASAReferenceKind.PROTOCOL_GROUP, protocol_object, "protocol")
        if getattr(rule, "icmp_object_group", None):
            resolve(ASAReferenceKind.ICMP_GROUP, rule.icmp_object_group, "icmp-object-group")
        for field, endpoint in (("source", getattr(rule, "source_endpoint", None)), ("destination", getattr(rule, "destination_endpoint", None))):
            if endpoint:
                kind = {"object": ASAReferenceKind.NETWORK_OBJECT, "object-group": ASAReferenceKind.NETWORK_GROUP}.get(endpoint.type)
                if kind:
                    resolve(kind, endpoint.value, field)
        for field, spec in (("source-service", getattr(rule, "source_port", None)), ("destination-service", getattr(rule, "destination_port", None))):
            if spec and spec.object_name:
                kind = ASAReferenceKind.SERVICE_GROUP if spec.operator == "object-group" else ASAReferenceKind.SERVICE_OBJECT
                resolve(kind, spec.object_name, field)
        resolve(ASAReferenceKind.TIME_RANGE, getattr(rule, "time_range", None), "time-range")
        resolve(ASAReferenceKind.LOCAL_USER, getattr(rule, "user", None), "user")
        resolve(ASAReferenceKind.USER_GROUP, getattr(rule, "user_group", None), "user-group")
        if getattr(rule, "source_security_group_type", None) == "object-group":
            resolve(ASAReferenceKind.SECURITY_GROUP, getattr(rule, "source_security_group_value", None), "source-security-group")
        if getattr(rule, "destination_security_group_type", None) == "object-group":
            resolve(ASAReferenceKind.SECURITY_GROUP, getattr(rule, "destination_security_group_value", None), "destination-security-group")
        item = ASAACLRuleRelationship(rule, tuple(targets), tuple(local))
        rule_rows.append(item)
        issues.extend(local)
    return ASAACLRelationships(tuple(rows), tuple(issues), tuple(rule_rows))
