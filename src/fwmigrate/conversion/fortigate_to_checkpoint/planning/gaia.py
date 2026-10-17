"""Restricted IPv4 and IPv6 Gaia static-route planning."""

from collections import Counter
from ipaddress import ip_address, ip_network

from ..models import CPMigrationItem
from .naming import item_key


def plan_gaia_routes(source, vdom, options):
    rows = []
    selected = [(index, route) for index, route in enumerate(source.static_routes)
                if (route.vdom or "root") == vdom]
    route_ids = [route.seq_num for _, route in selected if route.seq_num is not None]
    duplicate_ids = {route_id for route_id, count in Counter(route_ids).items() if count > 1}
    normalized_destinations = {}
    for order, route in selected:
        name = str(route.seq_num if route.seq_num is not None else order)
        duplicated = route.seq_num in duplicate_ids
        key = item_key(vdom, "static_route", f"{name}#duplicate:{order}") if duplicated else item_key(vdom, "static_route", name)
        blockers = []
        if duplicated:
            blockers.append("GAIA_ROUTE_ID_DUPLICATE")
        commands = ()
        if not options.gaia_target:
            blockers.append("GAIA_TARGET_REQUIRED")
        unsupported_fields = {"dstaddr", "device", "dynamic_gateway", "distance", "priority",
                             "vrf", "sdwan_zone", "src", "preferred_source"}
        if route.raw_extra or (set(route.explicit_fields) & unsupported_fields):
            blockers.append("GAIA_ROUTE_HAS_UNSUPPORTED_PATH_OR_SELECTION")
        if route.dstaddr or route.device or route.dynamic_gateway or route.blackhole not in ("disable", "disabled", "no"):
            blockers.append("GAIA_ROUTE_TARGET_PATH_UNREPRESENTABLE")
        if not {"dst", "gateway", "status", "blackhole"} <= set(route.explicit_fields):
            blockers.append("GAIA_ROUTE_DESTINATION_GATEWAY_ENABLED_AND_NON_BLACKHOLE_STATE_REQUIRED")
        if not route.dst or not route.gateway or str(route.status).casefold() not in {"enable", "enabled"}:
            blockers.append("GAIA_ROUTE_SOURCE_STATE_UNSUPPORTED")
        network = None
        command = None
        try:
            destination_parts = str(route.dst or "").split()
            if len(destination_parts) == 1:
                network = ip_network(destination_parts[0], strict=False)
            elif len(destination_parts) == 2:
                network = ip_network(f"{destination_parts[0]}/{destination_parts[1]}", strict=False)
            else:
                raise ValueError
            if network.version != (6 if route.address_family == "ipv6" else 4):
                raise ValueError
            gateway_address = ip_address(route.gateway)
            if gateway_address.version != network.version:
                raise ValueError
            command = (f"set ipv6 static-route {network} nexthop gateway {gateway_address} on"
                       if network.version == 6 else
                       f"set static-route {network} nexthop gateway address {gateway_address} on")
        except (TypeError, ValueError):
            blockers.append("GAIA_ROUTE_DESTINATION_OR_GATEWAY_INVALID")
        destination = str(network) if network is not None else None
        if destination:
            normalized_destinations.setdefault(destination, []).append(key)
        if command:
            commands = (command,)
        settings = (("gaia_commands", commands), ("gaia_target", options.gaia_target)) if commands else ()
        rows.append(CPMigrationItem(key, "static_route", vdom, name, destination or name,
                                    settings, blockers=tuple(dict.fromkeys(blockers)), source_order=order))
    duplicate_keys = {key for keys in normalized_destinations.values() if len(keys) > 1 for key in keys}
    adjusted = []
    for row in rows:
        blockers = list(row.blockers)
        if row.key in duplicate_keys:
            blockers.append("GAIA_MULTIPATH_OR_DUPLICATE_DESTINATION_UNSUPPORTED")
        adjusted.append(CPMigrationItem(row.key, row.family, row.source_vdom, row.source_name,
                                        row.target_name, row.settings, row.dependencies,
                                        tuple(dict.fromkeys(blockers)), row.source_order))
    return adjusted

