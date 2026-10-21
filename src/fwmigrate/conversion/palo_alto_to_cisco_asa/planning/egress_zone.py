"""Fail-closed proof that a complete IPv4 destination prefix exits one zone."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_network


@dataclass(frozen=True, slots=True)
class RouteZone:
    prefix: str
    zone: str


def prove_egress_zone(destination: str, routes: tuple[RouteZone, ...], *, routing_complete: bool,
                      segment_limit: int = 4096) -> str | None:
    """Return one egress zone only when every address selects a known, same-zone route.

    Equal-prefix ECMP to different zones is ambiguous. The caller must exclude dynamic,
    policy-based, NAT-dependent, or otherwise unmodeled forwarding from ``routes`` and
    set ``routing_complete`` only when the selected source scope is complete.
    """
    if not routing_complete or not 0 < segment_limit <= 65536:
        return None
    try:
        target = ip_network(destination, strict=False)
        candidates = [(ip_network(row.prefix, strict=False), row.zone) for row in routes]
    except (AttributeError, TypeError, ValueError):
        return None
    if not isinstance(target, IPv4Network) or any(not isinstance(network, IPv4Network) for network, _ in candidates):
        return None
    if any(not isinstance(zone, str) or not zone.strip() for _, zone in candidates):
        return None

    start, stop = int(target.network_address), int(target.broadcast_address) + 1
    boundaries = {start, stop}
    for network, _ in candidates:
        left = max(start, int(network.network_address))
        right = min(stop, int(network.broadcast_address) + 1)
        if left < right:
            boundaries.update((left, right))
            if len(boundaries) - 1 > segment_limit:
                return None

    zones = set()
    points = sorted(boundaries)
    for left, right in zip(points, points[1:]):
        address = IPv4Address(left)
        matching = [(network.prefixlen, zone) for network, zone in candidates if address in network]
        if not matching:
            return None
        longest = max(prefix for prefix, _ in matching)
        selected_zones = {zone for prefix, zone in matching if prefix == longest}
        if len(selected_zones) != 1:
            return None
        zones.update(selected_zones)
        if len(zones) != 1:
            return None
    return next(iter(zones), None)
