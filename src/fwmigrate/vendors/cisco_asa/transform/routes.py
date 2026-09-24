"""Derived route destination and documented effective distance."""

from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any


@dataclass(frozen=True, slots=True)
class ASARouteView:
    source_context: str | None
    source_route: Any
    address_family: str
    configured_destination: str | None
    configured_mask: str | None
    normalized_destination: str | None
    interface: str | None
    gateway: str | None
    configured_administrative_distance: int | None
    effective_administrative_distance: int
    track_id: int | None
    resolved_track: Any = None
    resolved_sla: Any = None
    tunneled: bool = False
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASARouteTransformResult:
    routes: tuple[ASARouteView, ...] = ()
    issues: tuple[str, ...] = ()


def transform_routes(config: Any, relationships: Any) -> ASARouteTransformResult:
    links = {id(row.route): row for row in relationships.static_routes}
    slas = {row.track.track_id: row.sla_monitor for row in relationships.tracks}
    result, issues = [], []
    for route in config.static_routes:
        local = []
        try:
            network = ip_network(f"{route.destination}/{route.mask}", strict=False) if route.address_family == "ipv4" else ip_network(route.destination, strict=False)
            if route.address_family == "ipv4" and not isinstance(network, IPv4Network): raise ValueError
            if route.address_family == "ipv6" and not isinstance(network, IPv6Network): raise ValueError
            normalized = str(network)
        except (ValueError, TypeError):
            normalized = None; local.append("Route destination cannot be normalized")
        relation = links.get(id(route))
        view = ASARouteView(route.source_context, route, route.address_family, route.destination, route.mask,
            normalized, route.interface, route.gateway, route.administrative_distance,
            route.administrative_distance if route.administrative_distance is not None else 1,
            route.track_id, relation.track if relation else None, slas.get(route.track_id), route.tunneled, tuple(local))
        result.append(view); issues.extend(local)
    return ASARouteTransformResult(tuple(result), tuple(issues))
