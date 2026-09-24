"""Read-only route, track, SLA, and policy-route dependencies."""

from dataclasses import dataclass
from typing import Any

from .references import ASAReferenceIndex


@dataclass(frozen=True, slots=True)
class ASAStaticRouteRelationship:
    route: Any
    interface: Any = None
    track: Any = None


@dataclass(frozen=True, slots=True)
class ASATrackRelationship:
    track: Any
    sla_monitor: Any = None


@dataclass(frozen=True, slots=True)
class ASASLARelationship:
    sla_monitor: Any
    interface: Any = None


@dataclass(frozen=True, slots=True)
class ASARouteMapRelationship:
    route_map: Any
    acl_targets: tuple[Any, ...] = ()
    interface_targets: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class ASARoutingRelationships:
    static_routes: tuple[ASAStaticRouteRelationship, ...] = ()
    tracks: tuple[ASATrackRelationship, ...] = ()
    sla_monitors: tuple[ASASLARelationship, ...] = ()
    route_maps: tuple[ASARouteMapRelationship, ...] = ()
    interface_policy_routes: tuple[tuple[Any, Any], ...] = ()
    issues: tuple[Any, ...] = ()


def build_routing_relationships(config: Any, references: ASAReferenceIndex) -> ASARoutingRelationships:
    from .references import ASAReferenceIssue, ASAReferenceKind, ASAReferenceStatus
    issues = []
    def get(ctx, kind, source, name, field):
        if name is None: return None
        result = references.resolve(ctx, kind, str(name))
        if result.status is not ASAReferenceStatus.RESOLVED:
            issues.append(ASAReferenceIssue(ctx, kind, source, str(name), result.status, f"Unresolved {kind.value} reference", field))
        return result.target
    routes = tuple(ASAStaticRouteRelationship(route, get(route.source_context, ASAReferenceKind.INTERFACE, route.raw_line or "static route", route.interface, "static-route"), get(route.source_context, ASAReferenceKind.TRACK, route.raw_line or "static route", route.track_id, "static-route")) for route in config.static_routes)
    tracks = tuple(ASATrackRelationship(item, get(item.source_context, ASAReferenceKind.SLA_MONITOR, item.name, item.sla_id, "track")) for item in config.tracks)
    slas = tuple(ASASLARelationship(item, get(item.source_context, ASAReferenceKind.INTERFACE, item.name, item.interface, "sla-interface")) for item in config.sla_monitors)
    maps = []
    for route_map in config.route_maps:
        acls = []; interfaces = []
        for rule in route_map.rules:
            for name in rule.match_acls or ([rule.match_acl] if rule.match_acl else []):
                target = get(route_map.source_context, ASAReferenceKind.ACL, route_map.name, name, "route-map-match")
                if target is not None: acls.append(target)
            for name in rule.output_interfaces or ([rule.set_interface] if rule.set_interface else []):
                target = get(route_map.source_context, ASAReferenceKind.INTERFACE, route_map.name, name, "route-map-set")
                if target is not None: interfaces.append(target)
        maps.append(ASARouteMapRelationship(route_map, tuple(acls), tuple(interfaces)))
    interface_routes = []
    for interface in config.interfaces:
        for name in interface.policy_route_maps:
            target = get(interface.source_context, ASAReferenceKind.ROUTE_MAP, interface.name, name, "policy-route-map")
            if target is not None:
                interface_routes.append((interface, target))
    return ASARoutingRelationships(routes, tracks, slas, tuple(maps), tuple(interface_routes), tuple(issues))
