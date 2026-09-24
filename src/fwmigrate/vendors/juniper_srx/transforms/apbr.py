"""Explicit APBR/AppQoE named-reference graph."""

from ..resolver import JuniperReferenceResolver


def _edge(scope, source_type, source_name, relationship, target_type, target_name, resolved):
    return {"context": scope, "source_type": source_type, "source_name": source_name,
            "relationship": relationship, "target_type": target_type, "target_name": target_name,
            "resolved": bool(resolved)}


def build_apbr_graph(context, scope: str) -> tuple[dict, ...]:
    apbr = context.apbr
    resolver = JuniperReferenceResolver(context)
    edges = []
    for group in apbr.destination_path_groups.values():
        if group.probe_routing_instance:
            edges.append(_edge(scope, "destination-path-group", group.name, "PROBE_ROUTING_INSTANCE",
                               "routing-instance", group.probe_routing_instance,
                               group.probe_routing_instance in context.routing_instances))
        for reference in group.overlay_paths:
            edges.append(_edge(scope, "destination-path-group", group.name, "OVERLAY_PATH", "overlay-path",
                               reference, reference in apbr.overlay_paths))
    for rule in apbr.sla_rules.values():
        for relationship, target_type, reference, collection in (
            ("METRICS_PROFILE", "metrics-profile", rule.metrics_profile, apbr.metrics_profiles),
            ("ACTIVE_PROBE_PARAMS", "active-probe-params", rule.active_probe_params, apbr.active_probe_params),
            ("PASSIVE_PROBE_PARAMS", "passive-probe-params", rule.passive_probe_params, apbr.passive_probe_params),
            ("MULTIPATH_RULE", "multipath-rule", rule.multipath_rule, apbr.multipath_rules),
        ):
            if reference:
                edges.append(_edge(scope, "sla-rule", rule.name, relationship, target_type, reference,
                                   reference in collection))
    for rule in apbr.multipath_rules.values():
        for reference in rule.applications:
            is_app, is_set, canonical = resolver.resolve_application(reference)
            edges.append(_edge(scope, "multipath-rule", rule.name, "APPLICATION", "application", reference,
                               is_app or canonical is not None))
        for reference in rule.application_groups:
            edges.append(_edge(scope, "multipath-rule", rule.name, "APPLICATION_SET", "application-set", reference,
                               reference in context.application_sets))
    return tuple(edges)
