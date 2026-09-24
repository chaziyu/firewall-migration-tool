from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..model import CiscoFTDRoute, CiscoFTDStaticRoute


@dataclass(frozen=True)
class NormalizedFTDRoute:
    source_name: str
    address_family: str | None
    configured_destination: str | None
    configured_mask: str | None
    normalized_destination: str | None
    gateway: str | None
    issue: str | None = None
    device_id: str | None = None
    virtual_router: str | None = None


def normalize_ftd_routes(routes: list[CiscoFTDStaticRoute | CiscoFTDRoute], network_addresses=()) -> tuple[NormalizedFTDRoute, ...]:
    by_id = {item.source_id: item.value for item in network_addresses if item.source_id}
    by_name = {item.name: item.value for item in network_addresses}
    result = []
    for route in routes:
        normalized = None
        issue = None
        family = (route.address_family or "").casefold()
        if isinstance(route, CiscoFTDRoute):
            destination = route.destination
            configured = (destination.value if destination and destination.value is not None else
                          by_id.get(destination.source_id) if destination else None)
            if configured is None and destination and destination.name:
                configured = by_name.get(destination.name)
            gateway_ref = route.gateway
            gateway_value = gateway_ref.value if gateway_ref and gateway_ref.value is not None else (
                gateway_ref.name or gateway_ref.source_id if gateway_ref else None)
            if configured is not None:
                try:
                    parsed = ipaddress.ip_network(str(configured), strict=False)
                    if parsed.version == (6 if family == "ipv6" else 4):
                        normalized = str(parsed)
                except ValueError:
                    pass
            if normalized and gateway_value:
                try:
                    ipaddress.ip_address(str(gateway_value))
                except ValueError:
                    pass
            configured_reference = (destination.name or destination.source_id or str(destination.value)
                                    if destination else None)
            result.append(NormalizedFTDRoute(route.name, route.address_family,
                configured_reference,
                None, normalized, str(gateway_value) if gateway_value is not None else None,
                None, route.device_id, route.virtual_router))
            continue
        try:
            if family == "ipv4":
                if not route.destination or not route.mask:
                    raise ValueError("IPv4 destination and mask are required")
                normalized = str(ipaddress.IPv4Network(f"{route.destination}/{route.mask}", strict=False))
            elif family == "ipv6":
                if not route.destination:
                    raise ValueError("IPv6 destination is required")
                normalized = str(ipaddress.IPv6Network(route.destination, strict=False))
            else:
                raise ValueError("Route address family is unknown")
            if route.gateway:
                gateway = ipaddress.ip_address(route.gateway)
                expected = 4 if family == "ipv4" else 6
                if gateway.version != expected:
                    raise ValueError("Gateway address family does not match route")
        except ValueError as exc:
            issue = f"Invalid FTD static route: {exc}"
            normalized = None
        result.append(NormalizedFTDRoute(route.name, route.address_family, route.destination,
            route.mask, normalized, route.gateway, issue))
    return tuple(result)
