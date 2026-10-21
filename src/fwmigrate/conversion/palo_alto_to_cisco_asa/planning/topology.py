"""Bounded physical topology and complete connected/static forwarding evidence."""

from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from .egress_zone import RouteZone
from .objects import _item
from .source_scope import in_scope


def device_scope(row, selected):
    return bool(row.scope and (in_scope(row, selected) or row.scope.kind == "device"
                and row.scope.device_name == selected.device_name))


def plan_topology(source, selected, options):
    zones = [row for row in source.zones if in_scope(row, selected)]
    memberships = {}
    topology_ok = bool(zones)
    for zone in zones:
        extra = zone.model_dump(exclude={"name", "source_path", "scope", "source_order", "explicit_fields", "raw_extra", "network_type", "members", "description", "tags"})
        if (zone.raw_extra or zone.network_type != "layer3" or not zone.name or not zone.members
                or any(value is not None and value != [] and value != {} for value in extra.values())):
            topology_ok = False
        for name in zone.members or ():
            memberships.setdefault(name, []).append(zone.name)
    interfaces = [row for row in source.interfaces if device_scope(row, selected)]
    # Unmapped ports, logical interfaces and other VSYS ownership could change forwarding.
    topology_ok &= (len([scope for scope in source.scopes if scope.kind == "vsys"]) == 1
                    and not source.interface_units and not source.logical_routers
                    and not source.sdwan_rules and not source.sdwan_interface_profiles
                    and set(memberships) == {row.name for row in interfaces}
                    and len(interfaces) == len({row.name for row in interfaces}))
    items, by_source, routes = [], {}, []
    for obj in interfaces:
        blockers, settings = [], {}
        mapping = options.interfaces.get(obj.name)
        if not topology_ok or len(memberships.get(obj.name, ())) != 1:
            blockers.append("INTERFACE_ZONE_OR_OWNERSHIP_UNVERIFIED")
        if (obj.raw_extra or obj.interface_family != "ethernet" or obj.mode != "layer3"
                or obj.ipv6_addresses or len(obj.ipv4_addresses or ()) != 1
                or obj.management_profile or obj.link_state or obj.speed or obj.duplex or obj.mtu or obj.vlan
                or obj.aggregate_group or obj.sdwan_enabled or obj.ipv6_sdwan_enabled
                or obj.sdwan_interface_profile or obj.upstream_nat or obj.lldp_enable):
            blockers.append("INTERFACE_EXPLICIT_SEMANTICS_UNSUPPORTED")
        try:
            address = IPv4Interface((obj.ipv4_addresses or [None])[0])
            if address.ip.is_multicast or address.ip.is_unspecified:
                raise ValueError
            if len(memberships.get(obj.name, ())) == 1:
                routes.append(RouteZone(str(address.network), memberships[obj.name][0]))
            if mapping:
                settings = {"interface": mapping.target_interface, "nameif": mapping.nameif,
                            "security_level": mapping.security_level, "address": str(address),
                            "source_zone": memberships.get(obj.name, [None])[0]}
        except (ValueError, TypeError):
            blockers.append("INTERFACE_IPV4_REQUIRED")
        if not mapping:
            blockers.append("INTERFACE_TARGET_MAPPING_REQUIRED")
        item = _item(obj, "interface", mapping.target_interface if mapping else obj.name,
                     settings.items(), blockers=blockers)
        by_source[obj.name] = item
        items.append(item)
    routers = [row for row in source.virtual_routers if device_scope(row, selected)]
    complete = bool(options.routing_complete and topology_ok and len(routers) == 1
                    and all(not row.blockers for row in items)
                    and not any(row.raw_extra for row in source.interface_imports))
    if len(routers) != 1:
        complete = False
    for router in routers:
        if (router.raw_extra or any((router.bgp, router.ospf, router.ospfv3, router.rip, router.redistribution_profiles))
                or set(router.interfaces or ()) != set(by_source)):
            complete = False
        for route in router.static_routes or ():
            blockers, settings, deps = [], {}, []
            interface = by_source.get(route.interface)
            if interface:
                deps.append(interface.key)
            try:
                network = IPv4Network(route.destination, strict=False)
                gateway = IPv4Address(route.nexthop_ip_address)
                values = dict(interface.settings) if interface and not interface.blockers else {}
                link = IPv4Interface(values["address"])
                if (gateway not in link.network or gateway == link.ip
                        or gateway in {link.network.network_address, link.network.broadcast_address}
                        or route.nexthop_type != "ip-address" or route.address_family != "ipv4"
                        or route.raw_extra or route.path_monitor or route.bfd_profile
                        or route.route_table not in {None, "unicast"}
                        or route.metric not in {None, "10"}):
                    raise ValueError
                # ASA static distance is explicit; source preference is not silently inferred.
                if route.admin_distance is None or not 1 <= int(route.admin_distance) <= 255:
                    raise ValueError
                settings = {"destination": str(network), "gateway": str(gateway),
                            "distance": int(route.admin_distance), "nameif": values["nameif"]}
                routes.append(RouteZone(str(network), values["source_zone"]))
            except (ValueError, TypeError, KeyError):
                blockers.append("ROUTE_FORWARDING_SEMANTICS_UNPROVEN")
                complete = False
            items.append(_item(route, "static_route", f"{router.name}-{route.name}", settings.items(), deps, blockers))
    # Equal prefixes need distance/metric/ECMP selection; initial proof rejects all duplicates.
    prefixes = [route.prefix for route in routes]
    if len(prefixes) != len(set(prefixes)):
        complete = False
    return items, by_source, memberships, tuple(routes), complete
