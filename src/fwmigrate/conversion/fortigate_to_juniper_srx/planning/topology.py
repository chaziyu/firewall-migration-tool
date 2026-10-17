"""SRX Layer 3 interfaces, security zones and simple static routes."""

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from dataclasses import replace
import re

from fwmigrate.vendors.fortigate.relationships.references import ReferenceKind

from ..models import SRXPlanItem
from ..options import SRXMigrationOptions
from ..requirements import source_vdoms
from .naming import decision_key, item_key, target_name


def _ipv4_interface(value):
    parts = str(value or "").split()
    if len(parts) != 2:
        return None
    try:
        return IPv4Interface(f"{parts[0]}/{parts[1]}")
    except ValueError:
        return None


def _route_destination(value):
    parts = str(value or "").split()
    try:
        if len(parts) == 2:
            return str(IPv4Network(f"{parts[0]}/{parts[1]}", strict=False))
        if len(parts) == 1:
            return str(IPv4Network(parts[0], strict=False))
    except ValueError:
        return None
    return None


def _mapped_interface(options, vdom, name):
    return options.interfaces.get(vdom, {}).get(name)


def _logical_name(mapping):
    return f"{mapping.target_interface}.{mapping.unit}"


def _settings(**values):
    return tuple(values.items())


def _global_blockers(options):
    blockers = []
    checks = (
        ("target_context", "root", "TARGET_CONTEXT_REQUIRED", "TARGET_CONTEXT_UNSUPPORTED"),
        ("target_version", "25.2R1", "TARGET_VERSION_REQUIRED", "TARGET_VERSION_UNVERIFIED"),
        ("target_mode", "standalone", "TARGET_MODE_REQUIRED", "LOGICAL_SYSTEMS_UNSUPPORTED"),
        ("routing_table", "inet.0", "ROUTING_TABLE_REQUIRED", "ROUTING_TABLE_UNSUPPORTED"),
    )
    for field, supported, missing, unsupported in checks:
        value = getattr(options, field)
        if value is None:
            blockers.append(missing)
        elif value != supported:
            blockers.append(unsupported)
    return tuple(blockers)


def plan_topology(source, derived, options: SRXMigrationOptions, vdom):
    interfaces = [item for item in source.interfaces if item.vdom == vdom]
    zones = [item for item in source.zones if item.vdom == vdom]
    topology_by_name = {item.name: item for item in derived.topology.interfaces if item.vdom == vdom}
    interface_items = {}
    target_owners = {}
    physical_target_owners = {}
    global_blockers = _global_blockers(options)

    for order, interface in enumerate(interfaces):
        blockers = list(global_blockers)
        topology = topology_by_name.get(interface.name)
        if topology is None:
            blockers.append("INTERFACE_TOPOLOGY_UNRESOLVED")
        elif topology.issues:
            blockers.append("INTERFACE_TOPOLOGY_HAS_ISSUES")
        if topology is not None and topology.kind not in {"physical", "vlan"}:
            blockers.append("INTERFACE_KIND_UNSUPPORTED")
        if any(row.kind is ReferenceKind.INTERFACE and row.vdom == vdom and row.name == interface.name
               for row in derived.references.duplicates):
            blockers.append("DUPLICATE_SOURCE_INTERFACE")
        if not {"mode", "status", "ip"} <= interface.explicit_fields:
            blockers.append("INTERFACE_MODE_STATUS_OR_IPV4_NOT_EXPLICIT")
        if interface.mode != "static" or interface.status != "up":
            blockers.append("INTERFACE_IS_NOT_EXPLICITLY_STATIC_AND_UP")
        if interface.secondary_ips:
            blockers.append("INTERFACE_SECONDARY_IP_UNSUPPORTED")
        if interface.vrf not in {None, 0}:
            blockers.append("INTERFACE_VRF_UNSUPPORTED")
        address = _ipv4_interface(interface.ip)
        if address is None:
            blockers.append("INTERFACE_IPV4_ADDRESS_AND_MASK_INVALID")
        mapping = _mapped_interface(options, vdom, interface.name)
        if mapping is None:
            blockers.append("INTERFACE_TARGET_MAPPING_REQUIRED")
        else:
            owner_key = (mapping.target_interface.casefold(), mapping.unit)
            target_owners.setdefault(owner_key, []).append(interface.name)
            if topology is not None and topology.kind == "physical" and (mapping.unit != 0 or topology.parent):
                blockers.append("PHYSICAL_INTERFACE_REQUIRES_EXPLICIT_UNIT_ZERO")
            if topology is not None and topology.kind == "physical":
                physical_target_owners.setdefault(mapping.target_interface.casefold(), []).append(interface.name)
            if topology is not None and topology.kind == "vlan":
                blockers.append("VLAN_PLATFORM_COMPATIBILITY_UNVERIFIED")
                parent = topology.parent
                parent_mapping = _mapped_interface(options, vdom, parent or "")
                if not parent or not parent_mapping:
                    blockers.append("VLAN_PARENT_MAPPING_REQUIRED")
                elif mapping.target_interface.casefold() != parent_mapping.target_interface.casefold():
                    blockers.append("VLAN_TARGET_INTERFACE_DIFFERS_FROM_MAPPED_PARENT")
                if "vlanid" not in interface.explicit_fields or interface.vlanid is None or not 1 <= interface.vlanid <= 4094:
                    blockers.append("VLAN_ID_NOT_EXPLICIT_OR_VALID")
                if mapping.unit == 0:
                    blockers.append("VLAN_REQUIRES_NONZERO_TARGET_UNIT")
        item = SRXPlanItem(
            key=item_key(vdom, "interface", interface.name),
            family="interface",
            source_vdom=vdom,
            source_name=interface.name,
            target_name=_logical_name(mapping) if mapping else target_name("interface", vdom, interface.name),
            settings=_settings(
                physical_interface=mapping.target_interface if mapping else None,
                unit=mapping.unit if mapping else None,
                vlan_id=interface.vlanid if topology is not None and topology.kind == "vlan" else None,
                ipv4_address=str(address) if address else None,
                source_kind=topology.kind if topology else None,
            ),
            dependencies=(item_key(vdom, "interface", topology.parent),)
                if topology is not None and topology.kind == "vlan" and topology.parent else (),
            decision_keys=(decision_key(vdom, "interface", interface.name, "target_interface"),),
            blockers=tuple(dict.fromkeys((*blockers, *(["INTERFACE_HAS_MANAGEMENT_ACCESS_UNSUPPORTED"] if interface.allowaccess else []),
                *(["INTERFACE_HAS_UNSUPPORTED_SOURCE_SETTINGS"] if interface.raw_extra else [])))),
            source_order=order,
        )
        interface_items[interface.name] = item

    for (target_interface, unit), names in target_owners.items():
        if len(names) > 1:
            for name in names:
                item = interface_items[name]
                interface_items[name] = replace(
                    item, blockers=tuple(dict.fromkeys((*item.blockers, "DUPLICATE_TARGET_INTERFACE_OWNERSHIP")))
                )
    for names in physical_target_owners.values():
        if len(names) > 1:
            for name in names:
                item = interface_items[name]
                interface_items[name] = replace(
                    item, blockers=tuple(dict.fromkeys((*item.blockers, "DUPLICATE_TARGET_PHYSICAL_INTERFACE")))
                )

    zone_items = {}
    zone_mappings = options.zones.get(vdom, {})
    target_zone_owners = {}
    for order, zone in enumerate(zones):
        target_zone = zone_mappings.get(zone.name)
        blockers = list(global_blockers)
        if target_zone is None:
            blockers.append("ZONE_TARGET_MAPPING_REQUIRED")
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", target_zone):
            blockers.append("ZONE_TARGET_NAME_INVALID")
        else:
            target_zone_owners.setdefault(target_zone.casefold(), []).append(zone.name)
        if "members" not in zone.explicit_fields or not zone.members:
            blockers.append("ZONE_MEMBERS_NOT_EXPLICIT")
        target_interfaces = []
        dependencies = []
        for member in zone.members:
            source_member = derived.references.get(ReferenceKind.INTERFACE, vdom=vdom, name=member)
            item = interface_items.get(member)
            if source_member is None or item is None:
                blockers.append("ZONE_INTERFACE_MEMBER_UNRESOLVED")
                continue
            target_interfaces.append(item.target_name)
            dependencies.append(item.key)
            if item.blockers:
                blockers.append("ZONE_INTERFACE_MEMBER_BLOCKED")
        key = item_key(vdom, "zone", zone.name)
        zone_items[zone.name] = SRXPlanItem(
            key=key,
            family="zone",
            source_vdom=vdom,
            source_name=zone.name,
            target_name=target_zone or target_name("zone", vdom, zone.name),
            settings=_settings(interfaces=tuple(target_interfaces), intrazone=zone.intrazone),
            dependencies=tuple(dict.fromkeys(dependencies)),
            decision_keys=(decision_key(vdom, "zone", zone.name, "target_zone"),),
            blockers=tuple(dict.fromkeys(blockers)),
            source_order=order,
        )
    for owners in target_zone_owners.values():
        if len(owners) > 1:
            for name in owners:
                item = zone_items[name]
                zone_items[name] = replace(
                    item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_ZONE_MERGES_SOURCE_ZONES")))
                )

    route_destinations = {}
    routes = [item for item in source.static_routes if item.vdom == vdom]
    for route in routes:
        destination = _route_destination(route.dst) if "dst" in route.explicit_fields else None
        if destination:
            route_destinations.setdefault(destination, []).append(route)
    route_items = []
    for order, route in enumerate(routes):
        blockers = list(global_blockers)
        if route.address_family != "ipv4":
            blockers.append("IPV6_STATIC_ROUTE_UNSUPPORTED")
        destination = _route_destination(route.dst) if "dst" in route.explicit_fields else None
        gateway = None
        try:
            if "gateway" in route.explicit_fields and route.gateway:
                gateway = str(IPv4Address(route.gateway))
        except ValueError:
            pass
        if destination is None:
            blockers.append("STATIC_ROUTE_DESTINATION_NOT_EXPLICIT_IPV4")
        if gateway is None:
            blockers.append("STATIC_ROUTE_GATEWAY_NOT_EXPLICIT_IPV4")
        if "device" not in route.explicit_fields or not route.device:
            blockers.append("STATIC_ROUTE_INTERFACE_NOT_EXPLICIT")
        if "distance" not in route.explicit_fields or route.distance is None:
            blockers.append("STATIC_ROUTE_DISTANCE_NOT_EXPLICIT")
        elif type(route.distance) is not int or not 0 <= route.distance <= 4_294_967_295:
            blockers.append("STATIC_ROUTE_DISTANCE_INVALID_FOR_TARGET")
        if route.priority is not None or route.vrf not in {None, 0} or route.src or route.preferred_source:
            blockers.append("STATIC_ROUTE_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if route.dynamic_gateway or route.sdwan_zone or route.blackhole:
            blockers.append("STATIC_ROUTE_FORWARDING_MODE_UNSUPPORTED")
        interface = derived.references.get(ReferenceKind.INTERFACE, vdom=vdom, name=route.device or "")
        interface_item = interface_items.get(route.device or "")
        if interface is None or interface_item is None:
            blockers.append("STATIC_ROUTE_INTERFACE_UNRESOLVED")
        elif interface_item.blockers:
            blockers.append("STATIC_ROUTE_INTERFACE_BLOCKED")
        if gateway and interface is not None:
            source_interface = next((item for item in interfaces if item.name == route.device), None)
            source_network = _ipv4_interface(source_interface.ip) if source_interface else None
            if source_network is None or IPv4Address(gateway) not in source_network.network:
                blockers.append("STATIC_ROUTE_GATEWAY_NOT_ON_SOURCE_INTERFACE_NETWORK")
        if destination and len(route_destinations.get(destination, ())) > 1:
            blockers.append("STATIC_ROUTE_DESTINATION_OVERLAP_UNSUPPORTED")
        name = str(route.seq_num) if route.seq_num is not None else f"route-{order + 1}"
        route_items.append(SRXPlanItem(
            key=item_key(vdom, "static_route", name),
            family="static_route",
            source_vdom=vdom,
            source_name=name,
            target_name=target_name("static_route", vdom, name),
            settings=_settings(
                destination=destination,
                next_hop=gateway,
                interface=interface_item.target_name if interface_item else None,
                preference=route.distance if "distance" in route.explicit_fields else None,
                routing_table=options.routing_table,
            ),
            dependencies=(interface_item.key,) if interface_item else (),
            blockers=tuple(dict.fromkeys(blockers)),
            source_order=order,
        ))

    return [*interface_items.values(), *zone_items.values(), *route_items]
