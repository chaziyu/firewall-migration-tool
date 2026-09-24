"""Junos NAT rule ownership and pool usage views."""

from ..resolver import JuniperReferenceResolver


def build_nat_usage(context, scope: str, effective_lookup=None) -> dict:
    resolver = JuniperReferenceResolver(context, effective_lookup)
    rules, pool_usage = [], []
    for nat_type, rule_sets in (("source", context.nat.source_rule_sets),
                                ("destination", context.nat.destination_rule_sets),
                                ("static", context.nat.static_rule_sets)):
        for rule_set in rule_sets.values():
            for order, rule in enumerate(rule_set.rules):
                action = rule.action or {}
                pool = action.get("pool_name")
                addresses = []
                for field in ("prefix_name",):
                    reference = action.get(field)
                    if reference:
                        result = resolver.resolve_nat(reference)
                        addresses.append({"field": field, "reference": reference,
                                          "resolved": not result.is_unresolved})
                addresses.extend({"field": field, "reference": reference,
                                  "resolved": not resolver.resolve_nat(reference).is_unresolved}
                                 for field, values in (("source-address-name", rule.match.source_address_names),
                                                       ("destination-address-name", rule.match.destination_address_names))
                                 for reference in values)
                row = {"context": scope, "nat_type": nat_type, "rule_set_name": rule_set.name,
                       "rule_name": rule.name, "rule_order": order, "from_context": rule_set.from_context,
                       "to_context": rule_set.to_context, "action_type": action.get("type"),
                       "pool_name": pool, "pool_resolved": (resolver.resolve_nat_pool(pool, nat_type) is not None) if pool else None,
                       "address_references": tuple(addresses)}
                rules.append(row)
                if pool:
                    pool_usage.append({"context": scope, "nat_type": nat_type, "pool_name": pool,
                                       "rule_name": rule.name, "rule_set_name": rule_set.name,
                                       "resolved": resolver.resolve_nat_pool(pool, nat_type) is not None})
    return {"rules": tuple(rules), "pool_usage": tuple(pool_usage)}
