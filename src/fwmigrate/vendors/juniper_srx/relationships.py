"""Vendor-native Juniper reference relationships."""

from __future__ import annotations

import ipaddress

from fwmigrate.extraction.models import DependencyRecord

from .resolver import JuniperReferenceResolver


def build_juniper_dependencies(config) -> List[DependencyRecord]:
    """Return typed Junos object-reference results for the report registry."""
    dependencies: List[DependencyRecord] = []

    def add(context, path, obj, field, reference, expected, resolved, notes=None):
        dependencies.append(
            DependencyRecord(
                source_context=None if context.name == "root" else context.name,
                source_path=path,
                source_object=obj,
                source_field=field,
                reference=str(reference),
                expected_type=expected,
                result="RESOLVED" if resolved else "UNRESOLVED",
                target_path=path if resolved else None,
                notes=notes,
            )
        )

    def scalar_is_literal(value):
        if str(value).lower() in {"any", "any-ipv4", "any-ipv6"}:
            return True
        try:
            ipaddress.ip_network(str(value), strict=False)
            return True
        except ValueError:
            return False

    for context in config.contexts.values():
        interfaces = context.interfaces

        def interface_exists(reference):
            if reference in interfaces:
                return True
            if "." not in reference:
                return False
            parent, unit = reference.rsplit(".", 1)
            return parent in interfaces and unit in interfaces[parent].units

        for interface in interfaces.values():
            for unit in interface.units.values():
                add(context, "interfaces", f"{interface.name}.{unit.unit}", "parent", interface.name, "physical-interface", interface.name in interfaces)

        for zone in context.zones.values():
            for interface in zone.interfaces:
                add(context, "security zones", zone.name, "interfaces", interface, "interface", interface_exists(interface))

        for instance in context.routing_instances.values():
            for interface in instance.interfaces:
                add(context, "routing-instances", instance.name, "interfaces", interface, "interface", interface_exists(interface))

        for book in context.address_books.values():
            for zone in book.attached_zones:
                add(context, "security address-book", book.name, "attach zone", zone, "security-zone", zone in context.zones)

        resolver = JuniperReferenceResolver(context)
        for policy in [*context.policies, *context.global_policies]:
            for zone in [*policy.from_zones, *policy.to_zones]:
                add(context, "security policies", policy.name, "zone", zone, "security-zone", zone in context.zones)
            for field, references in (
                ("source-address", policy.source_addresses),
                ("destination-address", policy.destination_addresses),
            ):
                for reference in references:
                    if not scalar_is_literal(reference):
                        if policy.policy_scope == "global":
                            result = resolver.resolve_global_policy(reference)
                        elif field == "source-address":
                            result = resolver.resolve_policy_source(policy.from_zone, reference)
                        else:
                            result = resolver.resolve_policy_destination(policy.to_zone, reference)
                        add(context, "security policies", policy.name, field, reference, "address/address-set", not result.is_unresolved)
            for reference in policy.applications:
                exists = resolver.resolve_application(reference)[2] is not None
                add(context, "security policies", policy.name, "application", reference, "application/application-set", exists)
            profile_collections = {
                "idp-policy": context.idp_policies,
                "utm-policy": context.utm_policies,
                "ssl-proxy-profile": context.ssl_proxy_profiles,
                "security-intelligence": context.security_intelligence_profiles,
            }
            for profile_type, references in policy.security_profile_references.items():
                collection = profile_collections.get(profile_type)
                if collection is None:
                    continue
                for reference in references:
                    add(
                        context,
                        "security policies",
                        policy.name,
                        profile_type,
                        reference,
                        "source-profile",
                        resolver.resolve_named_reference(reference, collection) is not None,
                    )
            if policy.scheduler_name:
                add(context, "security policies", policy.name, "scheduler", policy.scheduler_name, "scheduler", resolver.resolve_scheduler(policy.scheduler_name) is not None)

        for nat_type, rule_sets in (
            ("source", context.nat.source_rule_sets),
            ("destination", context.nat.destination_rule_sets),
            ("static", context.nat.static_rule_sets),
        ):
            pools = context.nat.source_pools if nat_type == "source" else context.nat.destination_pools
            for pool in pools.values():
                if pool.routing_instance:
                    add(
                        context,
                        f"security nat {nat_type}",
                        pool.name,
                        "routing-instance",
                        pool.routing_instance,
                        "routing-instance",
                        pool.routing_instance in context.routing_instances,
                    )
            for rule_set in rule_sets.values():
                for zone in [*rule_set.from_context.zones, *(rule_set.to_context.zones if rule_set.to_context else [])]:
                    add(context, f"security nat {nat_type}", rule_set.name, "zone", zone, "security-zone", zone in context.zones)
                for interface in [*rule_set.from_context.interfaces, *(rule_set.to_context.interfaces if rule_set.to_context else [])]:
                    add(context, f"security nat {nat_type}", rule_set.name, "interface", interface, "interface", interface_exists(interface))
                for instance in [*rule_set.from_context.routing_instances, *(rule_set.to_context.routing_instances if rule_set.to_context else [])]:
                    add(context, f"security nat {nat_type}", rule_set.name, "routing-instance", instance, "routing-instance", instance in context.routing_instances)
                for rule in rule_set.rules:
                    action = rule.action or {}
                    pool_name = action.get("pool_name")
                    if pool_name:
                        add(context, f"security nat {nat_type}", rule.name, "pool", pool_name, f"{nat_type}-nat-pool", pool_name in pools)
                    prefix_name = action.get("prefix_name")
                    if prefix_name:
                        resolved = resolver.resolve_nat(prefix_name)
                        add(
                            context,
                            f"security nat {nat_type}",
                            rule.name,
                            "static-prefix-name",
                            prefix_name,
                            "address/address-set",
                            not resolved.is_unresolved,
                        )
                    for field, references in (
                        ("source-address-name", rule.match.source_address_names),
                        ("destination-address-name", rule.match.destination_address_names),
                    ):
                        for reference in references:
                            resolved = resolver.resolve_nat(reference)
                            add(
                                context,
                                f"security nat {nat_type}",
                                rule.name,
                                field,
                                reference,
                                "address/address-set",
                                not resolved.is_unresolved,
                            )

        for route in context.routes:
            if route.routing_instance:
                add(
                    context,
                    "routing-instances" if route.routing_instance else "routing-options",
                    route.destination,
                    "routing-instance",
                    route.routing_instance,
                    "routing-instance",
                    route.routing_instance in context.routing_instances,
                )
            for next_hop in route.next_hops:
                reference = next_hop.value
                if scalar_is_literal(reference):
                    continue
                looks_like_interface = (
                    "/" in reference
                    or "." in reference
                    or reference.lower().startswith(("ae", "reth", "irb", "lo", "st", "em", "fxp"))
                )
                if looks_like_interface:
                    add(
                        context,
                        "routing-instances" if route.routing_instance else "routing-options",
                        route.destination,
                        "next-hop",
                        reference,
                        "interface",
                        interface_exists(reference),
                    )

        for interface in interfaces.values():
            for unit in interface.units.values():
                for attachment in unit.filters:
                    name = attachment.get("name")
                    family = attachment.get("family", "inet")
                    if name:
                        add(context, "firewall filters", f"{interface.name}.{unit.unit}", "filter", name, "firewall-filter", name in context.firewall_filters and context.firewall_filters[name].family.lower() == str(family).lower())
                    filt = context.firewall_filters.get(name)
                    if not filt:
                        continue
                    for term in filt.terms:
                        for action in term.actions:
                            if action.get("action") == "routing-instance":
                                ref = action.get("value")
                                add(context, "firewall filters", f"{name}:{term.name}", "routing-instance", ref, "routing-instance", isinstance(ref, str) and ref in context.routing_instances)
                            elif action.get("action") == "next-interface":
                                ref = action.get("value")
                                add(context, "firewall filters", f"{name}:{term.name}", "next-interface", ref, "interface", isinstance(ref, str) and interface_exists(ref))

    return dependencies

