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
class ASADHCPRelayInterfaceRelationship:
    relay_server: Any
    interface: Any = None


@dataclass(frozen=True, slots=True)
class ASAAllocatedInterfaceRelationship:
    context: Any
    allocation: Any
    interface: Any = None


@dataclass(frozen=True, slots=True)
class ASAPathMonitorRelationship:
    interface: Any
    monitor: Any
    status: str = "SOURCE_ONLY"


@dataclass(frozen=True, slots=True)
class ASARoutingRelationships:
    static_routes: tuple[ASAStaticRouteRelationship, ...] = ()
    tracks: tuple[ASATrackRelationship, ...] = ()
    sla_monitors: tuple[ASASLARelationship, ...] = ()
    route_maps: tuple[ASARouteMapRelationship, ...] = ()
    interface_policy_routes: tuple[tuple[Any, Any], ...] = ()
    dhcp_relay_interfaces: tuple[ASADHCPRelayInterfaceRelationship, ...] = ()
    allocated_interfaces: tuple[ASAAllocatedInterfaceRelationship, ...] = ()
    dhcp_server_interfaces: tuple[ASADHCPRelayInterfaceRelationship, ...] = ()
    dhcp_reservation_interfaces: tuple[ASADHCPRelayInterfaceRelationship, ...] = ()
    path_monitors: tuple[ASAPathMonitorRelationship, ...] = ()
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
    dhcp_interfaces = tuple(
        ASADHCPRelayInterfaceRelationship(
            entry,
            get(relay.source_context, ASAReferenceKind.INTERFACE, relay.name, entry.interface, "dhcp-relay-interface"),
        )
        for relay in getattr(config, "dhcp_relays", ())
        for entry in relay.server_entries
        if entry.interface
    )
    allocated_interfaces = tuple(
        ASAAllocatedInterfaceRelationship(
            context,
            entry,
            get(context.source_context, ASAReferenceKind.INTERFACE, context.name, entry.physical_interface, "allocated-interface"),
        )
        for context in getattr(config, "contexts", ())
        for entry in context.allocated_interface_entries
    )
    dhcp_server_interfaces = tuple(
        ASADHCPRelayInterfaceRelationship(server, get(server.source_context, ASAReferenceKind.INTERFACE, server.name, server.interface, "dhcp-server-interface"))
        for server in getattr(config, "dhcp_servers", ()) if server.interface
    )
    reservation_interfaces = tuple(
        ASADHCPRelayInterfaceRelationship(reservation, get(server.source_context, ASAReferenceKind.INTERFACE, server.name, reservation.interface, "dhcp-reservation-interface"))
        for server in getattr(config, "dhcp_servers", ())
        for reservation in server.reservations
    )
    path_monitors = tuple(
        ASAPathMonitorRelationship(interface, monitor)
        for interface in config.interfaces for monitor in interface.policy_route_path_monitors
    )
    return ASARoutingRelationships(
        static_routes=routes, tracks=tracks, sla_monitors=slas, route_maps=tuple(maps),
        interface_policy_routes=tuple(interface_routes), dhcp_relay_interfaces=dhcp_interfaces,
        allocated_interfaces=allocated_interfaces, dhcp_server_interfaces=dhcp_server_interfaces,
        dhcp_reservation_interfaces=reservation_interfaces, path_monitors=path_monitors, issues=tuple(issues),
    )
