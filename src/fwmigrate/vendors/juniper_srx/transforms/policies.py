"""Scope-aware Junos security policy ordering and references."""

from ..resolver import JuniperReferenceResolver


def build_policy_relationships(context, scope: str, effective_lookup=None) -> dict:
    resolver = JuniperReferenceResolver(context, effective_lookup)
    zone_groups = {}
    zone_orders = {}
    edges = []
    for policy in context.policies:
        from_zones = policy.from_zones or ([policy.from_zone] if policy.from_zone else [])
        to_zones = policy.to_zones or ([policy.to_zone] if policy.to_zone else [])
        key = (from_zones[0] if from_zones else None, to_zones[0] if to_zones else None)
        order = zone_orders.get(key, 0)
        zone_orders[key] = order + 1
        zone_groups.setdefault(key, []).append({"context": scope, "policy_scope": "zone", "from_zone": key[0],
                                                 "to_zone": key[1], "name": policy.name, "order": order,
                                                 "source_identities": tuple(policy.source_identities)})
        _policy_edges(edges, resolver, context, scope, policy)
    globals_ = []
    for order, policy in enumerate(context.global_policies):
        globals_.append({"context": scope, "policy_scope": "global",
                         "from_zone": tuple(policy.from_zones) or None,
                         "to_zone": tuple(policy.to_zones) or None,
                         "name": policy.name, "order": order,
                         "source_identities": tuple(policy.source_identities)})
        _policy_edges(edges, resolver, context, scope, policy)
    return {"zone_policy_sets": tuple({"from_zone": pair[0], "to_zone": pair[1], "policies": tuple(items)}
                                       for pair, items in zone_groups.items()),
            "global_policies": tuple(globals_), "edges": tuple(edges)}


def _policy_edges(edges, resolver, context, scope, policy):
    def add(field, target_type, reference, resolved, relationship=None):
        source_effective = resolver.policy_reference_is_effective(policy, field, reference)
        edges.append({"context": scope, "policy_scope": policy.policy_scope, "source_type": "security-policy",
                      "source_name": policy.name, "source_field": field,
                      "relationship": relationship or field.upper().replace("-", "_"),
                      "target_type": target_type, "target_name": reference, "resolved": bool(resolved),
                      "source_effective": source_effective,
                      "status": "INACTIVE_SOURCE" if not source_effective else
                      "RESOLVED" if resolved else "UNRESOLVED"})
    for field, references, zone, source in (("source-address", policy.source_addresses, policy.from_zone, True),
                                            ("destination-address", policy.destination_addresses, policy.to_zone, False)):
        for reference in references:
            result = resolver.resolve_global_policy(reference) if policy.policy_scope == "global" else (
                resolver.resolve_policy_source(zone, reference) if source else resolver.resolve_policy_destination(zone, reference))
            add(field, "address/address-set", reference, not result.is_unresolved)
    for reference in policy.applications:
        app, app_set, canonical = resolver.resolve_application(reference)
        add("application", "application-set" if app_set else "application", reference,
            app or app_set or canonical is not None)
    for field, reference, resolved in (("scheduler", policy.scheduler_name,
                                        resolver.resolve_scheduler(policy.scheduler_name) if policy.scheduler_name else None),):
        if reference:
            add(field, "scheduler", reference, resolved is not None)
    for profile_type, references in policy.security_profile_references.items():
        for reference in references:
            add(profile_type, "source-profile", reference,
                resolver.resolve_source_profile(profile_type, reference) is not None)
    if policy.vpn_reference:
        add("vpn-reference", "ipsec-vpn", policy.vpn_reference,
            resolver.resolve_ipsec_vpn(policy.vpn_reference) is not None, "EXPLICIT_VPN_REFERENCE")
