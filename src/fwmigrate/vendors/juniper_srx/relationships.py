"""Vendor-native Juniper reference relationships."""

from __future__ import annotations

import ipaddress

from fwmigrate.extraction.models import DependencyRecord

from .resolver import JuniperReferenceResolver


def _dependency(context, path, obj, field, reference, expected, resolved, source_effective=True):
    return DependencyRecord(
        source_context=None if context.context_type == "root" else f"{context.context_type} {context.name}",
        source_path=path, source_object=obj, source_field=field, reference=str(reference),
        expected_type=expected, result=("INACTIVE_SOURCE" if not source_effective else
                                        "RESOLVED" if resolved else "UNRESOLVED"),
        target_path=path if resolved else None)


def build_dhcp_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    for group in context.dhcp.local_servers.values():
        if group.routing_instance:
            dependencies.append(_dependency(context, "system services dhcp-local-server", group.name,
                                            "routing-instance", group.routing_instance, "routing-instance",
                                            resolver.resolve_routing_instance(group.routing_instance) is not None))
        for reference in group.interfaces:
            dependencies.append(_dependency(context, "system services dhcp-local-server", group.name,
                                            "interface", reference, "interface",
                                            resolver.resolve_interface(reference) is not None))
    for group in context.dhcp.relay_groups.values():
        if group.routing_instance:
            dependencies.append(_dependency(context, "system services dhcp-relay", group.name,
                                            "routing-instance", group.routing_instance, "routing-instance",
                                            resolver.resolve_routing_instance(group.routing_instance) is not None))
        for reference in group.interfaces:
            dependencies.append(_dependency(context, "system services dhcp-relay", group.name,
                                            "interface", reference, "interface",
                                            resolver.resolve_interface(reference) is not None))
    pools = tuple(context.dhcp.address_assignment_pools.values())
    for pool in pools:
        if pool.routing_instance:
            dependencies.append(_dependency(context, "access address-assignment", pool.name,
                                            "routing-instance", pool.routing_instance, "routing-instance",
                                            resolver.resolve_routing_instance(pool.routing_instance) is not None))
        if pool.linked_pool:
            resolved = any(item.name == pool.linked_pool and item.routing_instance == pool.routing_instance for item in pools)
            dependencies.append(_dependency(context, "access address-assignment", pool.name, "link",
                                            pool.linked_pool, "address-assignment-pool", resolved))
    return dependencies


def build_apbr_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    apbr = context.apbr
    for group in apbr.destination_path_groups.values():
        if group.probe_routing_instance:
            dependencies.append(_dependency(context, "security advance-policy-based-routing", group.name,
                                            "probe-routing-instance", group.probe_routing_instance,
                                            "routing-instance", resolver.resolve_routing_instance(group.probe_routing_instance) is not None,
                                            resolver.apbr_reference_is_effective("destination-path-group", group.name,
                                                                                "probe-routing-instance", group.probe_routing_instance)))
        for reference in group.overlay_paths:
            dependencies.append(_dependency(context, "security advance-policy-based-routing", group.name,
                                            "overlay-path", reference, "overlay-path",
                                            resolver.resolve_apbr_overlay_path(reference) is not None,
                                            resolver.apbr_reference_is_effective("destination-path-group", group.name,
                                                                                "overlay-path", reference)))
    for rule in apbr.sla_rules.values():
        for field, reference, expected in (
            ("metrics-profile", rule.metrics_profile, "metrics-profile"),
            ("active-probe-params", rule.active_probe_params, "active-probe-params"),
            ("passive-probe-params", rule.passive_probe_params, "passive-probe-params"),
            ("multipath-rule", rule.multipath_rule, "multipath-rule"),
        ):
            if reference:
                dependencies.append(_dependency(context, "security advance-policy-based-routing", rule.name,
                                                field, reference, expected,
                                                resolver.resolve_apbr_named(reference, field) is not None,
                                                resolver.apbr_reference_is_effective("sla-rule", rule.name,
                                                                                    field, reference)))
    for rule in apbr.multipath_rules.values():
        for reference in rule.applications:
            dependencies.append(_dependency(context, "security advance-policy-based-routing", rule.name,
                                            "application", reference,
                                            "application", resolver.resolve_application(reference)[2] is not None,
                                            resolver.apbr_reference_is_effective("multipath-rule", rule.name,
                                                                                "application", reference)))
        for reference in rule.application_groups:
            dependencies.append(_dependency(context, "security advance-policy-based-routing", rule.name,
                                            "application-group", reference, "application-set",
                                            resolver.resolve_application(reference)[1],
                                            resolver.apbr_reference_is_effective("multipath-rule", rule.name,
                                                                                "application-group", reference)))
    return dependencies


def build_remote_access_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    for profile in context.remote_access.profiles.values():
        for field, reference, expected, resolved in (
            ("access-profile", profile.access_profile, "access-profile", resolver.resolve_access_profile(profile.access_profile)),
            ("client-config", profile.client_config, "remote-access-client-config", resolver.resolve_remote_access_client_config(profile.client_config)),
            ("ipsec-vpn", profile.ipsec_vpn, "ipsec-vpn", resolver.resolve_ipsec_vpn(profile.ipsec_vpn)),
        ):
            if reference:
                dependencies.append(_dependency(context, "security remote-access", profile.name, field,
                                                reference, expected, resolved is not None,
                                                resolver.remote_access_reference_is_effective(profile.name,
                                                                                              field, reference)))
    return dependencies


def _scalar_is_literal(value) -> bool:
    if str(value).lower() in {"any", "any-ipv4", "any-ipv6"}:
        return True
    try:
        ipaddress.ip_network(str(value), strict=False)
        return True
    except ValueError:
        return False


def build_interface_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    for interface in context.interfaces.values():
        if interface.aggregate_parent:
            dependencies.append(_dependency(context, "interfaces", interface.name, "aggregate-parent",
                                            interface.aggregate_parent, "aggregate-interface",
                                            resolver.resolve_interface(interface.aggregate_parent) is not None))
        if interface.redundant_parent:
            dependencies.append(_dependency(context, "interfaces", interface.name, "redundant-parent",
                                            interface.redundant_parent, "redundant-interface",
                                            resolver.resolve_interface(interface.redundant_parent) is not None))
        for unit in interface.units.values():
            dependencies.append(_dependency(context, "interfaces", f"{interface.name}.{unit.unit}",
                                            "parent", interface.name, "physical-interface",
                                            resolver.resolve_interface(interface.name) is not None))
    for zone in context.zones.values():
        for reference in zone.interfaces:
            dependencies.append(_dependency(context, "security zones", zone.name, "interfaces", reference,
                                            "interface", resolver.resolve_interface(reference) is not None))
    for instance in context.routing_instances.values():
        for reference in instance.interfaces:
            dependencies.append(_dependency(context, "routing-instances", instance.name, "interfaces", reference,
                                            "interface", resolver.resolve_interface(reference) is not None))
    return dependencies


def build_address_book_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    resolver = JuniperReferenceResolver(context, effective_lookup)
    return [_dependency(context, "security address-book", book.name, "attach zone", zone,
                        "security-zone", resolver.resolve_zone(zone) is not None)
            for book in context.address_books.values() for zone in book.attached_zones]


def build_policy_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    for policy in [*context.policies, *context.global_policies]:
        for field, zones in (("from-zone", policy.from_zones), ("to-zone", policy.to_zones)):
            for zone in zones:
                source_effective = (resolver.policy_reference_is_effective(policy, field, zone)
                                    if policy.policy_scope == "global" else resolver.policy_is_effective(policy))
                dependencies.append(_dependency(context, "security policies", policy.name, field, zone,
                                                "security-zone", resolver.resolve_zone(zone) is not None,
                                                source_effective))
        for field, references in (("source-address", policy.source_addresses),
                                  ("destination-address", policy.destination_addresses)):
            for reference in references:
                if _scalar_is_literal(reference):
                    continue
                result = (resolver.resolve_global_policy(reference) if policy.policy_scope == "global" else
                          resolver.resolve_policy_source(policy.from_zone, reference) if field == "source-address" else
                          resolver.resolve_policy_destination(policy.to_zone, reference))
                dependencies.append(_dependency(context, "security policies", policy.name, field, reference,
                                                "address/address-set", not result.is_unresolved,
                                                resolver.policy_reference_is_effective(policy, field, reference)))
        for reference in policy.applications:
            dependencies.append(_dependency(context, "security policies", policy.name, "application", reference,
                                            "application/application-set",
                                            resolver.resolve_application(reference)[2] is not None,
                                            resolver.policy_reference_is_effective(policy, "application", reference)))
        for profile_type, references in policy.security_profile_references.items():
            for reference in references:
                dependencies.append(_dependency(context, "security policies", policy.name, profile_type,
                                                reference, "source-profile",
                                                resolver.resolve_source_profile(profile_type, reference) is not None,
                                                resolver.policy_reference_is_effective(policy, profile_type, reference)))
        if policy.scheduler_name:
            dependencies.append(_dependency(context, "security policies", policy.name, "scheduler",
                                            policy.scheduler_name, "scheduler",
                                            resolver.resolve_scheduler(policy.scheduler_name) is not None,
                                            resolver.policy_reference_is_effective(policy, "scheduler", policy.scheduler_name)))
    return dependencies


def build_nat_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    for nat_type, rule_sets in (("source", context.nat.source_rule_sets),
                                ("destination", context.nat.destination_rule_sets),
                                ("static", context.nat.static_rule_sets)):
        pools = context.nat.source_pools if nat_type == "source" else context.nat.destination_pools if nat_type == "destination" else {}
        for pool in pools.values():
            if pool.routing_instance:
                dependencies.append(_dependency(context, f"security nat {nat_type}", pool.name,
                                                "routing-instance", pool.routing_instance, "routing-instance",
                                                resolver.resolve_routing_instance(pool.routing_instance) is not None,
                                                resolver.nat_reference_is_effective(nat_type, pool.name, "",
                                                                                    "pool-routing-instance", pool.routing_instance)))
        for rule_set in rule_sets.values():
            for direction, source_context in (("from", rule_set.from_context), ("to", rule_set.to_context)):
                if source_context is None:
                    continue
                for kind, references, expected, resolve in (
                    ("zone", source_context.zones, "security-zone", resolver.resolve_zone),
                    ("interface", source_context.interfaces, "interface", resolver.resolve_interface),
                    ("routing-instance", source_context.routing_instances, "routing-instance", resolver.resolve_routing_instance),
                ):
                    for reference in references:
                        dependencies.append(_dependency(context, f"security nat {nat_type}", rule_set.name,
                                                        kind, reference, expected, resolve(reference) is not None,
                                                        resolver.nat_reference_is_effective(nat_type, rule_set.name, "",
                                                                                            f"{direction}-{kind}", reference)))
            for rule in rule_set.rules:
                pool_name = (rule.action or {}).get("pool_name")
                if pool_name:
                    dependencies.append(_dependency(context, f"security nat {nat_type}", rule.name, "pool",
                                                pool_name, f"{nat_type}-nat-pool",
                                                resolver.resolve_nat_pool(pool_name, nat_type) is not None,
                                                resolver.nat_reference_is_effective(nat_type, rule_set.name,
                                                                                    rule.name, "pool", pool_name)))
                prefix_name = (rule.action or {}).get("prefix_name")
                if prefix_name:
                    dependencies.append(_dependency(context, f"security nat {nat_type}", rule.name,
                                                    "static-prefix-name", prefix_name, "address/address-set",
                                                    not resolver.resolve_nat(prefix_name).is_unresolved,
                                                    resolver.nat_reference_is_effective(nat_type, rule_set.name,
                                                                                        rule.name, "prefix-name", prefix_name)))
                for field, references in (("source-address-name", rule.match.source_address_names),
                                          ("destination-address-name", rule.match.destination_address_names)):
                    for reference in references:
                        dependencies.append(_dependency(context, f"security nat {nat_type}", rule.name,
                                                        field, reference, "address/address-set",
                                                        not resolver.resolve_nat(reference).is_unresolved,
                                                        resolver.nat_reference_is_effective(nat_type, rule_set.name,
                                                                                            rule.name, field, reference)))
    return dependencies


def build_route_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    for route in context.routes:
        if route.routing_instance:
            dependencies.append(_dependency(context, "routing-instances", route.destination,
                                            "routing-instance", route.routing_instance, "routing-instance",
                                            resolver.resolve_routing_instance(route.routing_instance) is not None))
        for next_hop in route.next_hops:
            reference = next_hop.value
            if _scalar_is_literal(reference):
                continue
            looks_like_interface = ("/" in reference or "." in reference or
                                    reference.lower().startswith(("ae", "reth", "irb", "lo", "st", "em", "fxp")))
            if looks_like_interface:
                dependencies.append(_dependency(context,
                                                "routing-instances" if route.routing_instance else "routing-options",
                                                route.destination, "next-hop", reference, "interface",
                                                resolver.resolve_interface(reference) is not None))
    return dependencies


def build_firewall_filter_dependencies(context, effective_lookup=None) -> list[DependencyRecord]:
    dependencies = []
    resolver = JuniperReferenceResolver(context, effective_lookup)
    for interface in context.interfaces.values():
        for unit in interface.units.values():
            for attachment in unit.filters:
                name, family = attachment.get("name"), attachment.get("family", "inet")
                if name:
                    filt = context.firewall_filters.get(name)
                    dependencies.append(_dependency(context, "firewall filters", f"{interface.name}.{unit.unit}",
                                                    "filter", name, "firewall-filter",
                                                    resolver.resolve_firewall_filter(name, str(family)) is not None))
                filt = context.firewall_filters.get(name)
                if not filt:
                    continue
                for term in filt.terms:
                    for action in term.actions:
                        if action.get("action") == "routing-instance":
                            reference = action.get("value")
                            dependencies.append(_dependency(context, "firewall filters", f"{name}:{term.name}",
                                                            "routing-instance", reference, "routing-instance",
                                                            isinstance(reference, str) and resolver.resolve_routing_instance(reference) is not None))
                        elif action.get("action") == "next-interface":
                            reference = action.get("value")
                            dependencies.append(_dependency(context, "firewall filters", f"{name}:{term.name}",
                                                            "next-interface", reference, "interface",
                                                            isinstance(reference, str) and resolver.resolve_interface(reference) is not None))
    return dependencies


def build_juniper_dependencies(config, effective_lookup=None) -> list[DependencyRecord]:
    """Aggregate Juniper domain collectors for validation and reporting."""
    dependencies = []
    for context in config.iter_contexts():
        for collector in (build_dhcp_dependencies, build_interface_dependencies, build_address_book_dependencies,
                          build_policy_dependencies, build_nat_dependencies, build_remote_access_dependencies,
                          build_apbr_dependencies, build_route_dependencies, build_firewall_filter_dependencies):
            dependencies.extend(collector(context, effective_lookup))
    dependencies.extend(build_vpn_dependencies(config, effective_lookup))
    return dependencies


def build_vpn_dependencies(config, effective_lookup=None) -> list[DependencyRecord]:
    """Collect explicit VPN, Secure Connect, and policy-to-VPN references."""
    dependencies = []

    def add(context, path, source, field, reference, expected, resolved, source_effective=True):
        dependencies.append(DependencyRecord(
            source_context=None if context.context_type == "root" else f"{context.context_type} {context.name}",
            source_path=path, source_object=source, source_field=field, reference=str(reference),
            expected_type=expected, result=("INACTIVE_SOURCE" if not source_effective else
                                            "RESOLVED" if resolved else "UNRESOLVED"),
            target_path=path if resolved else None))

    for context in config.iter_contexts():
        resolver = JuniperReferenceResolver(context, effective_lookup)
        vpn = context.vpn
        for gateway in vpn.ike_gateways.values():
            if gateway.ike_policy:
                add(context, "security ike gateway", gateway.name, "ike-policy", gateway.ike_policy,
                    "ike-policy", resolver.resolve_ike_policy(gateway.ike_policy) is not None,
                    resolver.vpn_reference_is_effective("ike-gateway", gateway.name, "ike-policy", gateway.ike_policy))
            if gateway.certificate_reference:
                add(context, "security ike gateway", gateway.name, "certificate", gateway.certificate_reference,
                    "certificate", gateway.certificate_reference in config.pki.certificates)
        for policy in vpn.ike_policies.values():
            for reference in policy.proposals:
                add(context, "security ike policy", policy.name, "proposal", reference,
                    "ike-proposal", resolver.resolve_ike_proposal(reference) is not None,
                    resolver.vpn_reference_is_effective("ike-policy", policy.name, "proposal", reference))
            for field, reference in (("certificate", policy.certificate_reference), ("local-certificate", policy.local_certificate)):
                if reference:
                    add(context, "security ike policy", policy.name, field, reference,
                        "certificate", reference in config.pki.certificates)
        for policy in vpn.ipsec_policies.values():
            for reference in policy.proposals:
                add(context, "security ipsec policy", policy.name, "proposal", reference,
                    "ipsec-proposal", resolver.resolve_ipsec_proposal(reference) is not None,
                    resolver.vpn_reference_is_effective("ipsec-policy", policy.name, "proposal", reference))
        for tunnel in vpn.ipsec_vpns.values():
            if tunnel.ike_gateway:
                add(context, "security ipsec vpn", tunnel.name, "ike-gateway", tunnel.ike_gateway,
                    "ike-gateway", resolver.resolve_ike_gateway(tunnel.ike_gateway) is not None,
                    resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "ike-gateway", tunnel.ike_gateway))
            if tunnel.ipsec_policy:
                add(context, "security ipsec vpn", tunnel.name, "ipsec-policy", tunnel.ipsec_policy,
                    "ipsec-policy", resolver.resolve_ipsec_policy(tunnel.ipsec_policy) is not None,
                    resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "ipsec-policy", tunnel.ipsec_policy))
            if tunnel.bind_interface:
                add(context, "security ipsec vpn", tunnel.name, "bind-interface", tunnel.bind_interface,
                    "interface", resolver.resolve_interface(tunnel.bind_interface) is not None,
                    resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "bind-interface", tunnel.bind_interface))
            if tunnel.vpn_monitor and tunnel.vpn_monitor.source_interface:
                reference = tunnel.vpn_monitor.source_interface
                add(context, "security ipsec vpn monitor", tunnel.name, "source-interface", reference,
                    "interface", resolver.resolve_interface(reference) is not None,
                    resolver.vpn_reference_is_effective("ipsec-vpn", tunnel.name, "source-interface", reference))
        for policy in [*context.policies, *context.global_policies]:
            if policy.vpn_reference:
                add(context, "security policies", policy.name, "vpn-reference", policy.vpn_reference,
                    "ipsec-vpn", resolver.resolve_ipsec_vpn(policy.vpn_reference) is not None)
    return dependencies
