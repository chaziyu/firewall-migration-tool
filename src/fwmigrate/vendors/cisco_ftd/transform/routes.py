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
    source_id: str | None = None
    destination_index: int | None = None


def normalize_ftd_routes(routes: list[CiscoFTDStaticRoute | CiscoFTDRoute], network_addresses=()) -> tuple[NormalizedFTDRoute, ...]:
    by_id = {item.source_id: item.value for item in network_addresses if item.source_id}
    by_name = {item.name: item.value for item in network_addresses}

    def route_family(route):
        value = route.address_family or route.source_attributes.get("collection_address_family")
        return str(value).casefold() if value else ""

    def network_value(ref):
        if ref is None:
            return None
        if ref.value is not None:
            return ref.value
        if ref.source_id:
            return by_id.get(ref.source_id)
        if ref.name:
            return by_name.get(ref.name)
        return None

    result = []
    for route in routes:
        if isinstance(route, CiscoFTDStaticRoute):
            family = route_family(route)
            value = route.destination
            issue, normalized = None, None
            try:
                if family == "ipv4":
                    if not value or not route.mask:
                        raise ValueError("IPv4 destination and mask are required")
                    normalized = str(ipaddress.IPv4Network(f"{value}/{route.mask}", strict=False))
                elif family == "ipv6":
                    if not value:
                        raise ValueError("IPv6 destination is required")
                    normalized = str(ipaddress.IPv6Network(value, strict=False))
                else:
                    raise ValueError("Route address family is unknown")
                if route.gateway and route.gateway.casefold() != "null0":
                    gateway = ipaddress.ip_address(route.gateway)
                    if gateway.version != (6 if family == "ipv6" else 4):
                        raise ValueError("Gateway address family does not match route")
            except ValueError as exc:
                issue = f"Invalid FTD static route: {exc}"
            result.append(NormalizedFTDRoute(route.name, route.address_family, value, route.mask,
                normalized, route.gateway, issue))
            continue

        family = route_family(route)
        expected_version = 6 if family == "ipv6" else 4 if family == "ipv4" else None
        gateway_ref = route.gateway
        gateway_value = (gateway_ref.value if gateway_ref and gateway_ref.value is not None else
                         gateway_ref.name or gateway_ref.source_id if gateway_ref else None)
        gateway_text = str(gateway_value) if gateway_value is not None else None
        null_route = ((route.interface.name if route.interface else "").casefold() == "null0"
                      or (gateway_text or "").casefold() == "null0")
        refs = route.selected_networks if route.selected_networks is not None else (
            [route.destination] if route.destination is not None else [])
        if not refs:
            result.append(NormalizedFTDRoute(route.name, route.address_family, None, None, None,
                gateway_text, "Route destination is missing", route.device_id, route.virtual_router,
                route.source_id, None))
            continue

        for index, ref in enumerate(refs, 1):
            configured = network_value(ref)
            unresolved_object = configured is None and ref is not None and ref.source_type not in {"literal", "Literal"} and (
                ref.source_id is not None or ref.name is not None)
            normalized, issue = None, None
            if not family:
                issue = "Route address family is unknown"
            elif configured is not None:
                try:
                    network = ipaddress.ip_network(str(configured), strict=False)
                    if network.version != expected_version:
                        issue = "Route destination address family does not match configured family"
                    else:
                        normalized = str(network)
                except ValueError:
                    issue = "Route destination cannot be parsed"
            elif not unresolved_object:
                issue = "Route destination is missing"

            if gateway_value is not None and not null_route:
                literal_gateway = gateway_ref is None or gateway_ref.source_type == "literal" or gateway_ref.value is not None
                if literal_gateway:
                    try:
                        gateway = ipaddress.ip_address(str(gateway_value))
                        if expected_version and gateway.version != expected_version:
                            issue = "Route gateway address family does not match configured family"
                    except ValueError:
                        issue = "Route gateway cannot be parsed"
            destination_label = (str(configured) if configured is not None else
                                 ref.name or ref.source_id if ref is not None else None)
            result.append(NormalizedFTDRoute(route.name, route.address_family or route.source_attributes.get("collection_address_family"),
                destination_label, None, normalized, gateway_text, issue, route.device_id,
                route.virtual_router, route.source_id, index if route.selected_networks is not None else None))
    return tuple(result)
