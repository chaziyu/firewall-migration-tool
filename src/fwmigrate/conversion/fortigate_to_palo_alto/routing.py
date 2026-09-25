"""FortiGate static-route planning for Palo Alto."""

import ipaddress
from typing import Any

from .models import PANMigrationStatus, PlannedStaticRoute
from ...vendors.fortigate.relationships.references import ReferenceKind


def plan_routes(source: Any, options: Any, derived: Any = None):
    result = []
    for route in getattr(source, "static_routes", ()):
        warnings = []
        mapping = getattr(options, "vdoms", {}).get(route.vdom)
        virtual_router = mapping.virtual_router if mapping else None
        destination = route.dst
        if not destination and route.dstaddr:
            address = None
            references = getattr(derived, "references", None)
            if references is not None:
                address = references.get(ReferenceKind.ADDRESS, vdom=route.vdom or "root", name=route.dstaddr)
            destination = _explicit_subnet(address) if address is not None else None
            if destination is None:
                warnings.append(f"route destination reference {route.dstaddr!r} is not one deterministic subnet address")
        interface = None
        if route.device:
            interface_mapping = getattr(options, "interfaces", {}).get(route.vdom or "root", {}).get(route.device)
            if interface_mapping and interface_mapping.target_interface:
                interface = interface_mapping.target_interface
            else:
                warnings.append(f"missing target interface mapping for {route.device!r}")
        if not virtual_router:
            warnings.append("missing target virtual-router mapping")
        if not destination and not any("destination reference" in warning for warning in warnings):
            warnings.append("route has no explicit destination")
        if route.dynamic_gateway or route.sdwan_zone or route.src or route.vrf is not None:
            warnings.append("route uses unsupported source or dynamic routing semantics")
        status = PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW
        blackhole = getattr(route, "blackhole", None) in {"enable", "yes", "1"}
        nexthop = None if blackhole else route.gateway
        result.append(PlannedStaticRoute(
            source_vdom=route.vdom, source_kind="static_route", source_object_type="static_route",
            source_name=str(route.seq_num) if route.seq_num is not None else destination,
            source_policy_id=route.seq_num, status=status, warnings=tuple(warnings),
            target_vsys=getattr(mapping, "vsys", None), target_name=str(route.seq_num) if route.seq_num is not None else destination,
            destination=destination, nexthop_type="discard" if blackhole else ("ip-address" if nexthop else None),
            nexthop=nexthop, admin_distance=getattr(route, "distance", None), interface=interface,
            virtual_router=virtual_router, disabled=getattr(route, "status", None) in {"disable", "disabled"},
            description=getattr(route, "comment", None),
        ))
    return tuple(result)


def _explicit_subnet(address: Any) -> str | None:
    """Return only an explicitly configured, deterministic subnet value."""
    if address is None or getattr(address, "address_family", None) != "ipv4" or not getattr(address, "subnet", None):
        return None
    parts = str(address.subnet).split()
    try:
        if len(parts) == 1 and "/" in parts[0]:
            return str(ipaddress.ip_network(parts[0], strict=False))
        if len(parts) == 2:
            return str(ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False))
    except ValueError:
        return None
    return None
