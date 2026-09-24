from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..model import CiscoFTDStaticRoute


@dataclass(frozen=True)
class NormalizedFTDRoute:
    source_name: str
    address_family: str | None
    configured_destination: str | None
    configured_mask: str | None
    normalized_destination: str | None
    gateway: str | None
    issue: str | None = None


def normalize_ftd_routes(routes: list[CiscoFTDStaticRoute]) -> tuple[NormalizedFTDRoute, ...]:
    result = []
    for route in routes:
        normalized = None
        issue = None
        try:
            if route.address_family == "ipv4":
                if not route.destination or not route.mask:
                    raise ValueError("IPv4 destination and mask are required")
                normalized = str(ipaddress.IPv4Network(f"{route.destination}/{route.mask}", strict=False))
            elif route.address_family == "ipv6":
                if not route.destination:
                    raise ValueError("IPv6 destination is required")
                normalized = str(ipaddress.IPv6Network(route.destination, strict=False))
            else:
                raise ValueError("Route address family is unknown")
            if route.gateway:
                gateway = ipaddress.ip_address(route.gateway)
                expected = 4 if route.address_family == "ipv4" else 6
                if gateway.version != expected:
                    raise ValueError("Gateway address family does not match route")
        except ValueError as exc:
            issue = f"Invalid FTD static route: {exc}"
            normalized = None
        result.append(NormalizedFTDRoute(route.name, route.address_family, route.destination,
            route.mask, normalized, route.gateway, issue))
    return tuple(result)
