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
class ASAACLRelationships:
    bindings: tuple[ASAACLBindingRelationship, ...] = ()
    issues: tuple[Any, ...] = ()


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
    return ASAACLRelationships(tuple(rows), tuple(issues))
