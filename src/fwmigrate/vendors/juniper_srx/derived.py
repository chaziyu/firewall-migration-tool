"""Read-only Junos relationships and derived views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .coverage import build_juniper_dependencies


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


def build_juniper_derived_views(config: Any) -> JuniperDerivedViews:
    """Resolve relationships from source state without changing ``config``."""
    interfaces, zones, routes, books, apps, policies, nat, vpn = [], [], [], [], [], [], [], []
    for context in config.contexts.values():
        scope = context.name
        for interface in context.interfaces.values():
            for unit in interface.units.values():
                interfaces.append({"context": scope, "interface": interface.name, "unit": unit.unit,
                                   "parent": interface.name, "name": f"{interface.name}.{unit.unit}"})
        for zone in context.zones.values():
            zones.extend({"context": scope, "zone": zone.name, "interface": interface} for interface in zone.interfaces)
        routes.extend({"context": scope, "name": name, "interfaces": list(item.interfaces)}
                      for name, item in context.routing_instances.items())
        books.extend({"context": scope, "name": name, "zones": list(book.attached_zones),
                      "addresses": list(book.addresses), "address_sets": list(book.address_sets)}
                     for name, book in context.address_books.items())
        apps.extend({"context": scope, "name": name, "terms": list(getattr(item, "terms", []))}
                    for name, item in context.applications.items())
        policies.extend({"context": scope, "name": item.name, "order": index,
                         "from_zones": list(item.from_zones), "to_zones": list(item.to_zones)}
                        for index, item in enumerate([*context.policies, *context.global_policies]))
        for kind, sets in (("source", context.nat.source_rule_sets), ("destination", context.nat.destination_rule_sets),
                           ("static", context.nat.static_rule_sets)):
            nat.extend({"context": scope, "type": kind, "name": name,
                        "rules": [rule.name for rule in rules.rules]}
                       for name, rules in sets.items())
        vpn.extend({"context": scope, "name": name, "type": kind}
                   for kind, items in (("ike-proposal", context.vpn.ike_proposals), ("ike-policy", context.vpn.ike_policies),
                                       ("ike-gateway", context.vpn.ike_gateways), ("ipsec-vpn", context.vpn.ipsec_vpns))
                   for name in items)
    return JuniperDerivedViews(tuple(interfaces), tuple(zones), tuple(routes), tuple(books), tuple(apps),
                               tuple(policies), tuple(nat), tuple(vpn), tuple(build_juniper_dependencies(config)))


__all__ = ["JuniperDerivedViews", "build_juniper_derived_views"]
