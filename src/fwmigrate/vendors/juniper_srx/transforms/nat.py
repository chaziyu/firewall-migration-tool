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
                        source_effective = resolver.nat_reference_is_effective(
                            nat_type, rule_set.name, rule.name, "prefix-name", reference)
                        addresses.append({"field": field, "reference": reference,
                                          "resolved": not result.is_unresolved,
                                          **({"source_effective": False, "status": "INACTIVE_SOURCE"}
                                             if not source_effective else {})})
                for field, values in (("source-address-name", rule.match.source_address_names),
                                      ("destination-address-name", rule.match.destination_address_names)):
                    for reference in values:
                        result = resolver.resolve_nat(reference)
                        source_effective = resolver.nat_reference_is_effective(nat_type, rule_set.name,
                                                                                rule.name, field, reference)
                        addresses.append({"field": field, "reference": reference,
                                          "resolved": not result.is_unresolved,
                                          **({"source_effective": False, "status": "INACTIVE_SOURCE"}
                                             if not source_effective else {})})
                pool_resolved = resolver.resolve_nat_pool(pool, nat_type) is not None if pool else None
                pool_effective = (resolver.nat_reference_is_effective(nat_type, rule_set.name, rule.name,
                                                                       "pool", pool) if pool else None)
                row = {"context": scope, "nat_type": nat_type, "rule_set_name": rule_set.name,
                       "rule_name": rule.name, "rule_order": order, "from_context": rule_set.from_context,
                       "to_context": rule_set.to_context, "action_type": action.get("type"),
                       "pool_name": pool, "pool_resolved": pool_resolved,
                       "address_references": tuple(addresses)}
                if pool_effective is False:
                    row["pool_source_effective"] = False
                    row["pool_status"] = "INACTIVE_SOURCE"
                rules.append(row)
                if pool:
                    pool_usage.append({"context": scope, "nat_type": nat_type, "pool_name": pool,
                                       "rule_name": rule.name, "rule_set_name": rule_set.name,
                                       "resolved": pool_resolved,
                                       **({"source_effective": False, "status": "INACTIVE_SOURCE"}
                                          if pool_effective is False else {})})
    return {"rules": tuple(rules), "pool_usage": tuple(pool_usage)}
