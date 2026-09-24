"""Read-only Junos relationships and derived views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .relationships import build_juniper_dependencies
from .transforms import (
    build_apbr_graph,
    build_compatibility_views,
    build_inheritance_view,
    build_nat_usage,
    build_policy_relationships,
    build_secure_connect_graph,
    build_vpn_graph,
)


@dataclass(frozen=True)
class JuniperDerivedViews:
    interface_topology: tuple[dict[str, Any], ...] = ()
    zone_memberships: tuple[dict[str, Any], ...] = ()
    routing_instances: tuple[dict[str, Any], ...] = ()
    address_books: tuple[dict[str, Any], ...] = ()
    applications: tuple[dict[str, Any], ...] = ()
    policies: tuple[dict[str, Any], ...] = ()
    nat_rule_sets: tuple[dict[str, Any], ...] = ()
    vpn_relationships: tuple[dict[str, Any], ...] = ()
    dependencies: tuple[Any, ...] = ()
    inheritance: dict[str, tuple[dict[str, Any], ...]] = field(default_factory=dict)
    activation_directives: tuple[dict[str, Any], ...] = ()
    dhcp: tuple[dict[str, Any], ...] = ()
    access_profiles: tuple[dict[str, Any], ...] = ()
    firewall_users: tuple[dict[str, Any], ...] = ()
    apbr: tuple[dict[str, Any], ...] = ()
    remote_access: tuple[dict[str, Any], ...] = ()
    inheritance_view: dict[str, Any] = field(default_factory=dict)
    nat_usage: tuple[dict[str, Any], ...] = ()
    nat_pool_usage: tuple[dict[str, Any], ...] = ()
    policy_relationships: tuple[dict[str, Any], ...] = ()
    vpn_graph: tuple[dict[str, Any], ...] = ()
    secure_connect_graph: tuple[dict[str, Any], ...] = ()
    apbr_graph: tuple[dict[str, Any], ...] = ()


def build_juniper_derived_views(config: Any, source_commands=()) -> JuniperDerivedViews:
    """Resolve relationships from source state without changing ``config``."""
    compatibility = build_compatibility_views(config)
    nat_usage, nat_pool_usage, policy_views, vpn_graph, secure_connect, apbr_graph = [], [], [], [], [], []
    for context in config.iter_contexts():
        scope = context.name if context.context_type == "root" else f"{context.context_type} {context.name}"
        nat_view = build_nat_usage(context, scope)
        nat_usage.extend(nat_view["rules"])
        nat_pool_usage.extend(nat_view["pool_usage"])
        policy_views.append({"context": scope, **build_policy_relationships(context, scope)})
        vpn_graph.extend(build_vpn_graph(context, scope, config.pki.certificates))
        secure_connect.extend(build_secure_connect_graph(context, scope, config.pki.certificates))
        apbr_graph.extend(build_apbr_graph(context, scope))
    inheritance_view = build_inheritance_view(source_commands)
    inheritance = {"effective_commands": tuple(item for item in inheritance_view["effective_statements"]
                                                if item["origin"] == "inherited-group"),
                   "candidates": inheritance_view["candidates"]}
    inheritance["effective_commands"] = tuple({**item, "path": item["target_path"]}
                                               for item in inheritance["effective_commands"])
    activation = tuple(item.model_dump(mode="python") for item in config.activation_directives)
    return JuniperDerivedViews(
        **compatibility, dependencies=tuple(build_juniper_dependencies(config)), inheritance=inheritance,
        activation_directives=activation, inheritance_view=inheritance_view, nat_usage=tuple(nat_usage),
        nat_pool_usage=tuple(nat_pool_usage),
        policy_relationships=tuple(policy_views), vpn_graph=tuple(vpn_graph),
        secure_connect_graph=tuple(secure_connect), apbr_graph=tuple(apbr_graph))


__all__ = ["JuniperDerivedViews", "build_juniper_derived_views"]
