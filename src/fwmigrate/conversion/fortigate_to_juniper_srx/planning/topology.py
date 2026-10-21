"""SRX Layer 3 interfaces, security zones and simple static routes."""

from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from dataclasses import replace
import re

from fwmigrate.vendors.fortigate.relationships.references import ReferenceKind

from ..models import SRXPlanItem
from ..options import SRXMigrationOptions
from ..requirements import source_vdoms, standalone_interfaces
from .naming import decision_key, item_key, target_name
from .source_semantics import default_evidence, effective_fields, source_value


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
    control_plane_items = []
    target_owners = {}
    physical_target_owners = {}
    global_blockers = _global_blockers(options)
    tagged_parents = {row.interface for row in interfaces if row.type == "vlan" and row.interface}
    interface_defaults = effective_fields(derived, vdom, "interface")

    for order, interface in enumerate(interfaces):
        defaults = interface_defaults.get(interface.name, {})
        blockers = list(global_blockers)
        topology = topology_by_name.get(interface.name)
        if topology is None:
            blockers.append("INTERFACE_TOPOLOGY_UNRESOLVED")
        elif topology.issues:
            blockers.append("INTERFACE_TOPOLOGY_HAS_ISSUES")
        if topology is not None and topology.kind not in {"physical", "vlan"}:
            blockers.append("INTERFACE_KIND_UNSUPPORTED")
        if interface.type not in {"physical", "vlan", None} or (
            topology is not None and topology.kind == "physical" and interface.type != "physical"
        ):
            blockers.append("INTERFACE_TYPE_NOT_EXPLICIT_OR_SUPPORTED")
        if topology is not None and topology.kind == "physical" and interface.explicit_fields - {
            "vdom", "type", "mode", "status", "ip", "description", "alias", "allowaccess", "vrf", "role",
        }:
            blockers.append("INTERFACE_HAS_UNSUPPORTED_TYPED_SETTINGS")
        if any(row.kind is ReferenceKind.INTERFACE and row.vdom == vdom and row.name == interface.name
               for row in derived.references.duplicates):
            blockers.append("DUPLICATE_SOURCE_INTERFACE")
        if any(field not in interface.explicit_fields and field not in defaults for field in ("mode", "status", "ip")):
            blockers.append("INTERFACE_MODE_STATUS_OR_IPV4_NOT_EXPLICIT")
        if source_value(interface, "mode", defaults) != "static" or source_value(interface, "status", defaults) != "up":
            blockers.append("INTERFACE_IS_NOT_EXPLICITLY_STATIC_AND_UP")
        if interface.secondary_ips:
            blockers.append("INTERFACE_SECONDARY_IP_UNSUPPORTED")
        if interface.vrf not in {None, 0}:
            blockers.append("INTERFACE_VRF_UNSUPPORTED")
        address = _ipv4_interface(interface.ip)
        tagged_only = interface.name in tagged_parents and str(interface.ip).split() == ["0.0.0.0", "0.0.0.0"]
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
                if "type" not in interface.explicit_fields or interface.type != "vlan":
                    blockers.append("VLAN_TYPE_NOT_EXPLICIT")
                if interface.explicit_fields - {"type", "interface", "vlanid", "ip", "status", "mode", "vdom", "description", "alias"}:
                    blockers.append("VLAN_HAS_UNSUPPORTED_SOURCE_SETTINGS")
                if options.target_platform != "vsrx" or not options.vlan_interfaces_available:
                    blockers.append("VLAN_PLATFORM_COMPATIBILITY_UNVERIFIED")
                parent = topology.parent
                parent_mapping = _mapped_interface(options, vdom, parent or "")
                source_parent = next((row for row in interfaces if row.name == parent), None)
                # shortcut: tagged-only trunks avoid inventing a native VLAN for source untagged traffic.
                if source_parent is None or str(source_parent.ip).split() != ["0.0.0.0", "0.0.0.0"]:
                    blockers.append("VLAN_UNTAGGED_PARENT_ADDRESS_UNSUPPORTED")
                if not parent or not parent_mapping:
                    blockers.append("VLAN_PARENT_MAPPING_REQUIRED")
                elif mapping.target_interface.casefold() != parent_mapping.target_interface.casefold():
                    blockers.append("VLAN_TARGET_INTERFACE_DIFFERS_FROM_MAPPED_PARENT")
                if "vlanid" not in interface.explicit_fields or interface.vlanid is None or not 1 <= interface.vlanid <= 4094:
                    blockers.append("VLAN_ID_NOT_EXPLICIT_OR_VALID")
                if mapping.unit == 0:
                    blockers.append("VLAN_REQUIRES_NONZERO_TARGET_UNIT")
                if sum(row.interface == parent and row.type == "vlan" and row.vlanid == interface.vlanid
                       for row in interfaces) != 1:
                    blockers.append("VLAN_TAG_OWNERSHIP_AMBIGUOUS")
            if interface.name in tagged_parents and (tagged_only or options.target_platform == "vsrx"):
                if (options.target_platform != "vsrx" or not options.vlan_interfaces_available or not tagged_only
                        or interface.type != "physical" or "type" not in interface.explicit_fields
                        or interface.explicit_fields - {"type", "ip", "status", "mode", "vdom", "description", "alias"}
                        or not re.fullmatch(r"ge-0/0/\d+", mapping.target_interface)):
                    blockers.append("VLAN_TAGGED_ONLY_VSRX_PARENT_REQUIRED")
                if (any(interface.name in (zone.members or ()) for zone in zones)
                        or any(interface.name in (policy.srcintf or ()) or interface.name in (policy.dstintf or ())
                               for policy in source.policies if policy.vdom == vdom)
                        or any(route.device == interface.name for route in source.static_routes if route.vdom == vdom)):
                    blockers.append("VLAN_PARENT_LAYER3_MEMBERSHIP_UNSUPPORTED")
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
                ipv4_address=str(address) if address and not tagged_only else None,
                vlan_trunk=tagged_only,
                source_kind=topology.kind if topology else None,
                source_effective_values=default_evidence(defaults),
            ),
            dependencies=(item_key(vdom, "interface", topology.parent),)
                if topology is not None and topology.kind == "vlan" and topology.parent else (),
            decision_keys=(decision_key(vdom, "interface", interface.name, "target_interface"),),
            blockers=tuple(dict.fromkeys((*blockers,
                *(["INTERFACE_HAS_UNSUPPORTED_SOURCE_SETTINGS"] if set(interface.raw_extra) - {
                    "snmp-index", "monitor-bandwidth", "device-identification", "lldp-transmission",
                } else [])))),
            source_order=order,
        )
        interface_items[interface.name] = item
        observation = {key: value for key, value in interface.raw_extra.items()
                       if key in {"device-identification", "lldp-transmission"}}
        if interface.allowaccess or observation:
            control_plane_items.append(SRXPlanItem(
                key=item_key(vdom, "interface_control_plane", interface.name), family="interface_control_plane",
                source_vdom=vdom, source_name=interface.name,
                target_name=target_name("interface_control_plane", vdom, interface.name),
                settings=_settings(source_allowaccess=tuple(interface.allowaccess or ()), source_observation=observation),
                dependencies=(item.key,), blockers=("INTERFACE_CONTROL_PLANE_REQUIRES_SEPARATE_DESIGN",),
                source_order=order,
            ))

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
    for order, zone in enumerate(zones):
        target_zone = zone_mappings.get(zone.name)
        blockers = list(global_blockers)
        if target_zone is None:
            blockers.append("ZONE_TARGET_MAPPING_REQUIRED")
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", target_zone):
            blockers.append("ZONE_TARGET_NAME_INVALID")
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
        zone_items["zone", zone.name] = SRXPlanItem(
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
    for interface in standalone_interfaces(source, vdom):
        identity = ("interface", interface.name)
        target_zone = options.interface_zones.get(vdom, {}).get(interface.name)
        interface_item = interface_items[interface.name]
        blockers = list(global_blockers)
        if not target_zone:
            blockers.append("ZONE_TARGET_MAPPING_REQUIRED")
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", target_zone):
            blockers.append("ZONE_TARGET_NAME_INVALID")
        if interface_item.blockers:
            blockers.append("ZONE_INTERFACE_MEMBER_BLOCKED")
        zone_items[identity] = SRXPlanItem(
            key=item_key(vdom, "interface_zone", interface.name), family="zone", source_vdom=vdom,
            source_name=f"interface:{interface.name}", target_name=target_zone or target_name("zone", vdom, f"interface:{interface.name}"),
            settings=_settings(interfaces=(interface_item.target_name,), source_interface=interface.name),
            dependencies=(interface_item.key,),
            decision_keys=(decision_key(vdom, "interface", interface.name, "target_zone"),),
            blockers=tuple(dict.fromkeys(blockers)), source_order=len(zones) + len(zone_items),
        )
    owners = {}
    for identity, item in zone_items.items():
        owners.setdefault(item.target_name.casefold(), []).append(identity)
    for identities in owners.values():
        if len(identities) > 1:
            for identity in identities:
                item = zone_items[identity]
                zone_items[identity] = replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_ZONE_MERGES_SOURCE_ZONES"))))

    route_destinations = {}
    routes = [item for item in source.static_routes if item.vdom == vdom]
    route_defaults = effective_fields(derived, vdom, "static_route")
    for route in routes:
        defaults = route_defaults.get(str(route.seq_num), {})
        destination = _route_destination(source_value(route, "dst", defaults))
        if destination:
            route_destinations.setdefault(destination, []).append(route)
    route_items = []
    for order, route in enumerate(routes):
        defaults = route_defaults.get(str(route.seq_num), {})
        blockers = list(global_blockers)
        if source_value(route, "status", defaults) != "enable":
            blockers.append("STATIC_ROUTE_STATUS_NOT_EXPLICITLY_ENABLED")
        if route.address_family != "ipv4":
            blockers.append("IPV6_STATIC_ROUTE_UNSUPPORTED")
        destination = _route_destination(source_value(route, "dst", defaults))
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
        distance = source_value(route, "distance", defaults)
        if distance is None:
            blockers.append("STATIC_ROUTE_DISTANCE_NOT_EXPLICIT")
        elif type(distance) is not int or not 1 <= distance <= 255:
            blockers.append("STATIC_ROUTE_DISTANCE_INVALID_FOR_TARGET")
        if route.raw_extra or route.dstaddr or route.priority not in {None, 1} or route.vrf not in {None, 0} or route.src or route.preferred_source:
            blockers.append("STATIC_ROUTE_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if route.dynamic_gateway not in {None, "disable"} or route.sdwan_zone or route.blackhole not in {None, "disable"}:
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
                preference=distance,
                routing_table=options.routing_table,
                source_effective_values=default_evidence(defaults),
            ),
            dependencies=(interface_item.key,) if interface_item else (),
            blockers=tuple(dict.fromkeys(blockers)),
            source_order=order,
        ))

    return [*interface_items.values(), *control_plane_items, *zone_items.values(), *route_items]
