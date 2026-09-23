"""FortiGate static-route planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedStaticRoute


def plan_routes(source: Any, options: Any):
    result = []
    for route in getattr(source, "static_routes", ()):
        warnings = []
        mapping = getattr(options, "vdoms", {}).get(route.vdom)
        virtual_router = mapping.virtual_router if mapping else None
        destination = route.dst or route.dstaddr
        interface = None
        if route.device:
            interface_mapping = getattr(options, "interfaces", {}).get(route.device)
            if interface_mapping:
                interface = interface_mapping.target_interface
            else:
                warnings.append(f"missing target interface mapping for {route.device!r}")
        if not virtual_router:
            warnings.append("missing target virtual-router mapping")
        if not destination:
            warnings.append("route has no explicit destination")
        if route.dynamic_gateway or route.sdwan_zone or route.src or route.vrf is not None:
            warnings.append("route uses unsupported source or dynamic routing semantics")
        status = PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW
        result.append(PlannedStaticRoute(
            source_vdom=route.vdom, source_kind="static_route", source_object_type="static_route",
            source_name=str(route.seq_num) if route.seq_num is not None else destination,
            source_policy_id=route.seq_num, status=status, warnings=tuple(warnings),
            destination=destination, gateway=("discard" if route.blackhole in {"enable", "yes", "1"} else route.gateway),
            interface=interface, virtual_router=virtual_router,
        ))
    return tuple(result)
