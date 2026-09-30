"""Read-only Check Point policy traversal views."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model.policy import CPAccessLayer, CPAccessRule
from ..relationships.policy_structure import CPPolicyStructure


@dataclass(frozen=True, slots=True)
class CPPolicyTraversalIssue:
    message: str
    layer_uid: str | None = None
    rule_uid: str | None = None
    reference: str | None = None
    relationship_status: str | None = None


@dataclass(frozen=True, slots=True)
class CPPolicyTraversalEntry:
    domain: str | None
    package_uid: str | None
    package_name: str | None
    layer_uid: str | None
    layer_name: str | None
    section_uid: str | None
    section_name: str | None
    section_path: tuple[str, ...]
    rule_uid: str | None
    rule_name: str | None
    rule_order: int | None
    inline_depth: int
    parent_rule_uid: str | None
    parent_layer_uid: str | None
    traversal_position: int
    source_rule: CPAccessRule
    issues: tuple[CPPolicyTraversalIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class CPPolicyTraversalResult:
    entries: tuple[CPPolicyTraversalEntry, ...] = ()
    issues: tuple[CPPolicyTraversalIssue, ...] = ()


def build_policy_traversal(structure: CPPolicyStructure) -> CPPolicyTraversalResult:
    """Traverse resolved policy relationships without dropping unresolved source rules."""
    entries: list[CPPolicyTraversalEntry] = []
    issues: list[CPPolicyTraversalIssue] = []
    inline_by_rule = {id(item.parent_rule): item for item in structure.inline_layers}
    represented_rules: set[int] = set()

    def scope(value: Any) -> str:
        return value.domain_uid or value.domain or "global"

    def belongs_to_layer(rule: CPAccessRule, layer: CPAccessLayer) -> bool:
        if scope(rule) != scope(layer):
            return False
        if rule.layer_uid:
            return bool(layer.uid and rule.layer_uid == layer.uid)
        if rule.layer:
            return bool(layer.name and rule.layer == layer.name)
        return bool(rule.parent_layer_uid and layer.uid and rule.parent_layer_uid == layer.uid)

    def visit(layer: CPAccessLayer, package: Any, depth: int,
              parent_rule: CPAccessRule | None, parent_layer: CPAccessLayer | None,
              active: frozenset[str]) -> None:
        rules = [rule for rule in structure.rules if belongs_to_layer(rule, layer)]
        for rule in rules:
            represented_rules.add(id(rule))
            path = tuple(rule.section_path)
            section = next((item.section for item in structure.sections
                            if item.layer is layer and item.section_path == path), None)
            child = inline_by_rule.get(id(rule))
            child_layer = child.inline_layer if child else None
            rule_issues: list[CPPolicyTraversalIssue] = []
            if child and child.issue:
                issue = CPPolicyTraversalIssue(
                    child.issue.message or f"Inline-layer reference {child.issue.reference!r} is {child.issue.status}.",
                    child.parent_layer.uid if child.parent_layer else None,
                    rule.uid,
                    child.issue.reference,
                    child.issue.status,
                )
                rule_issues.append(issue)
                issues.append(issue)
            child_key = (child_layer.uid or child_layer.name or f"object:{id(child_layer)}") if child_layer else None
            if child_layer and child_key in active:
                issue = CPPolicyTraversalIssue(
                    f"Inline layer cycle detected at {child_layer.name or child_layer.uid!r}.",
                    child_layer.uid, rule.uid,
                )
                rule_issues.append(issue)
                issues.append(issue)
            entries.append(CPPolicyTraversalEntry(
                rule.domain_uid or rule.domain or layer.domain_uid or layer.domain or package.domain_uid or package.domain,
                package.uid, package.name, layer.uid, layer.name,
                section.uid if section else None,
                section.name if section else (path[-1] if path else None), path,
                rule.uid, rule.name, rule.order if rule.order is not None else rule.rule_number,
                depth, parent_rule.uid if parent_rule else None,
                parent_layer.uid if parent_layer else None, len(entries) + 1, rule,
                tuple(rule_issues),
            ))
            if child_layer and not rule_issues:
                visit(child_layer, package, depth + 1, rule, layer, active | {child_key})

    for relation in structure.package_layers:
        if relation.layer is not None:
            root_key = relation.layer.uid or relation.layer.name or f"object:{id(relation.layer)}"
            visit(relation.layer, relation.package, 0, None, None, frozenset({root_key}))

    for rule in structure.rules:
        if id(rule) in represented_rules:
            continue
        issue = CPPolicyTraversalIssue(
            "Rule is not reachable from resolved package/layer relationships; source rule retained for review.",
            rule.layer_uid,
            rule.uid,
            rule.layer_uid or rule.layer,
            "unresolved_owner",
        )
        issues.append(issue)
        path = tuple(rule.section_path)
        entries.append(CPPolicyTraversalEntry(
            rule.domain_uid or rule.domain,
            rule.package_uid,
            rule.package,
            rule.layer_uid,
            rule.layer,
            None,
            path[-1] if path else None,
            path,
            rule.uid,
            rule.name,
            rule.order if rule.order is not None else rule.rule_number,
            0,
            rule.parent_rule_uid,
            rule.parent_layer_uid,
            len(entries) + 1,
            rule,
            (issue,),
        ))

    return CPPolicyTraversalResult(tuple(entries), tuple(issues))


__all__ = ["CPPolicyTraversalEntry", "CPPolicyTraversalIssue", "CPPolicyTraversalResult", "build_policy_traversal"]
