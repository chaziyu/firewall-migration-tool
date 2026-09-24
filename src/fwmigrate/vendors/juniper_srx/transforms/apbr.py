"""Explicit APBR/AppQoE named-reference graph."""

from ..resolver import JuniperReferenceResolver


def _edge(scope, source_type, source_name, relationship, target_type, target_name, resolved,
          source_effective=True):
    return {"context": scope, "source_type": source_type, "source_name": source_name,
            "relationship": relationship, "target_type": target_type, "target_name": target_name,
            "resolved": bool(resolved), "source_effective": source_effective,
            "status": "INACTIVE_SOURCE" if not source_effective else
            "RESOLVED" if resolved else "UNRESOLVED"}


def build_apbr_graph(context, scope: str, effective_lookup=None) -> tuple[dict, ...]:
    apbr = context.apbr
    resolver = JuniperReferenceResolver(context, effective_lookup)
    edges = []
    for group in apbr.destination_path_groups.values():
        if group.probe_routing_instance:
            edges.append(_edge(scope, "destination-path-group", group.name, "PROBE_ROUTING_INSTANCE",
                               "routing-instance", group.probe_routing_instance,
                               resolver.resolve_routing_instance(group.probe_routing_instance) is not None,
                               resolver.apbr_reference_is_effective("destination-path-group", group.name,
                                                                   "probe-routing-instance", group.probe_routing_instance)))
        for reference in group.overlay_paths:
            edges.append(_edge(scope, "destination-path-group", group.name, "OVERLAY_PATH", "overlay-path",
                               reference, resolver.resolve_apbr_overlay_path(reference) is not None,
                               resolver.apbr_reference_is_effective("destination-path-group", group.name,
                                                                   "overlay-path", reference)))
    for rule in apbr.sla_rules.values():
        for relationship, target_type, reference in (
            ("METRICS_PROFILE", "metrics-profile", rule.metrics_profile),
            ("ACTIVE_PROBE_PARAMS", "active-probe-params", rule.active_probe_params),
            ("PASSIVE_PROBE_PARAMS", "passive-probe-params", rule.passive_probe_params),
            ("MULTIPATH_RULE", "multipath-rule", rule.multipath_rule),
        ):
            if reference:
                edges.append(_edge(scope, "sla-rule", rule.name, relationship, target_type, reference,
                                   resolver.resolve_apbr_named(reference, target_type) is not None,
                                   resolver.apbr_reference_is_effective("sla-rule", rule.name,
                                                                       relationship.lower().replace("_", "-"), reference)))
    for rule in apbr.multipath_rules.values():
        for reference in rule.applications:
            is_app, is_set, canonical = resolver.resolve_application(reference)
            edges.append(_edge(scope, "multipath-rule", rule.name, "APPLICATION", "application", reference,
                               is_app or canonical is not None,
                               resolver.apbr_reference_is_effective("multipath-rule", rule.name,
                                                                   "application", reference)))
        for reference in rule.application_groups:
            edges.append(_edge(scope, "multipath-rule", rule.name, "APPLICATION_SET", "application-set", reference,
                               resolver.resolve_application(reference)[1],
                               resolver.apbr_reference_is_effective("multipath-rule", rule.name,
                                                                   "application-group", reference)))
    return tuple(edges)
