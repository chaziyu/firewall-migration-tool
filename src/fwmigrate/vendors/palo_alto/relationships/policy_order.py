from __future__ import annotations

from dataclasses import dataclass

from ..model.source import PANOSConfig
from ..source_model import PANScope, pan_scope_identity
from .scopes import PANDeviceGroupHierarchy


@dataclass(frozen=True, slots=True)
class PANPolicyOrderEntry:
    rule_name: str | None
    source_scope: PANScope | None
    rulebase_position: str | None
    source_order: int | None
    target_scope: str
    effective_order: int
    rule_kind: str


def build_policy_order(config: PANOSConfig, hierarchy: PANDeviceGroupHierarchy) -> tuple[PANPolicyOrderEntry, ...]:
    rules = [*(('security', rule) for rule in config.security_rules), *(('default', rule) for rule in config.default_security_rules)]
    result: list[PANPolicyOrderEntry] = []
    targets = {pan_scope_identity(rule.scope): rule.scope for _, rule in rules if rule.scope}
    for target_id, target in targets.items():
        selected = []
        if target and target.kind == "device-group":
            chain = tuple(reversed(dict(hierarchy.ancestors).get(target.name, ()))) + (target.name,)
            scope_order = {f"device-group:{name}": index for index, name in enumerate(chain)}
            selected = [(kind, rule) for kind, rule in rules if rule.scope and ((rule.scope.kind == "device-group" and f"device-group:{rule.scope.name}" in scope_order) or rule.scope.kind == "shared")]
            selected.sort(key=lambda item: (0 if item[1].rulebase_position == "pre" else 2 if item[1].rulebase_position == "post" else 1, scope_order.get(f"device-group:{item[1].scope.device_group}", -1) if item[1].rulebase_position != "post" and item[1].scope.kind == "device-group" else -1 if item[1].scope.kind == "shared" else 0, item[1].source_order or 0))
        else:
            selected = [(kind, rule) for kind, rule in rules if pan_scope_identity(rule.scope) == target_id]
            selected.sort(key=lambda item: item[1].source_order or 0)
        result.extend(PANPolicyOrderEntry(rule.name, rule.scope, rule.rulebase_position, rule.source_order, target_id, offset, kind) for offset, (kind, rule) in enumerate(selected, 1))
    return tuple(result)
