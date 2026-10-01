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


def _ordered(items):
    return sorted(items, key=lambda item: item[1].source_order or 0)


def build_policy_order(
    config: PANOSConfig,
    hierarchy: PANDeviceGroupHierarchy,
) -> tuple[PANPolicyOrderEntry, ...]:
    """Build read-only effective security-rule order from explicit source state.

    Panorama device-group ordering is:
        shared pre
        -> ancestor pre (highest to lowest)
        -> target device-group pre
        -> target local rules, if explicitly present
        -> target device-group post
        -> ancestor post (lowest to highest)
        -> shared post
        -> target default rules

    This view does not infer firewall-to-device-group assignment.  Each
    device-group result is therefore the effective order visible from that
    device-group scope only.
    """
    security = [("security", rule) for rule in config.security_rules]
    defaults = [("default", rule) for rule in config.default_security_rules]
    rules = [*security, *defaults]

    targets = {
        pan_scope_identity(scope): scope
        for scope in config.scopes
        if scope.kind == "device-group"
    }
    targets.update(
        {
            pan_scope_identity(rule.scope): rule.scope
            for _, rule in rules
            if rule.scope is not None
        }
    )

    result: list[PANPolicyOrderEntry] = []
    for target_id, target in targets.items():
        selected: list[tuple[str, object]] = []

        if target.kind == "device-group":
            ancestors = dict(hierarchy.ancestors).get(target_id, ())
            chain = (*reversed(ancestors), target_id)

            def dg_rules(position: str, identities) -> list[tuple[str, object]]:
                ordered: list[tuple[str, object]] = []
                for identity in identities:
                    ordered.extend(_ordered([
                        (kind, rule)
                        for kind, rule in security
                        if rule.scope
                        and rule.scope.kind == "device-group"
                        and pan_scope_identity(rule.scope) == identity
                        and rule.rulebase_position == position
                    ]))
                return ordered

            shared_pre = [
                item for item in security
                if item[1].scope
                and item[1].scope.kind == "shared"
                and item[1].rulebase_position == "pre"
            ]
            shared_post = [
                item for item in security
                if item[1].scope
                and item[1].scope.kind == "shared"
                and item[1].rulebase_position == "post"
            ]
            local = [
                item for item in security
                if item[1].scope
                and pan_scope_identity(item[1].scope) == target_id
                and item[1].rulebase_position in {None, "local"}
            ]
            target_defaults = [
                item for item in defaults
                if item[1].scope
                and pan_scope_identity(item[1].scope) == target_id
            ]

            selected.extend(_ordered(shared_pre))
            selected.extend(dg_rules("pre", chain))
            selected.extend(_ordered(local))
            selected.extend(dg_rules("post", reversed(chain)))
            selected.extend(_ordered(shared_post))
            selected.extend(_ordered(target_defaults))
        else:
            exact = [
                item for item in security
                if item[1].scope
                and pan_scope_identity(item[1].scope) == target_id
            ]
            target_defaults = [
                item for item in defaults
                if item[1].scope
                and pan_scope_identity(item[1].scope) == target_id
            ]
            selected.extend(_ordered(exact))
            selected.extend(_ordered(target_defaults))

        result.extend(
            PANPolicyOrderEntry(
                rule.name,
                rule.scope,
                rule.rulebase_position,
                rule.source_order,
                target_id,
                offset,
                kind,
            )
            for offset, (kind, rule) in enumerate(selected, 1)
        )

    return tuple(result)
