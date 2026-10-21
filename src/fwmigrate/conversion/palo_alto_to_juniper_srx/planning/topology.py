"""Plan explicitly mapped PAN-OS L3 interfaces, zones and static routes."""

from ipaddress import IPv4Interface, IPv4Network, IPv4Address

from .source_scope import identity, in_scope
from .objects import _safe_name
from ..models import SRXPlanItem


def _topology_scope(item, selected):
    if in_scope(item, selected):
        return True
    scope = item.scope
    return bool(scope and scope.kind == "device" and selected.kind == "vsys" and
                (scope.device_serial or scope.device_name) == (selected.device_serial or selected.device_name))


def _item(obj, family, name, settings=(), dependencies=(), blockers=(), order=0):
    return SRXPlanItem(identity(obj, family), family, identity(obj, "scope"), family,
                       obj.name or "(unnamed)", obj.source_path, name, tuple(settings),
                       tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(blockers)), order)


def plan_interfaces(source, selected, options):
    result, by_source = [], {}
    selected_zones = [row for row in source.zones if in_scope(row, selected)]
    member_names = {name for zone in selected_zones for name in (zone.members or ())}
    unit_parents = {unit.parent for unit in source.interface_units if unit.name in member_names and unit.parent}
    member_names.update(unit_parents)
    for order, obj in enumerate([row for row in source.interfaces if _topology_scope(row, selected)
                                 and row.name in member_names]):
        mapping = options.interfaces.get(obj.name or "")
        blockers, settings = [], {}
        if obj.raw_extra or obj.interface_family != "ethernet" or obj.mode != "layer3":
            blockers.append("INTERFACE_MUST_BE_EXPLICIT_L3_ETHERNET")
        tagged_parent = obj.name in unit_parents and obj.name not in {name for zone in selected_zones for name in (zone.members or ())}
        if tagged_parent:
            if obj.ipv4_addresses or obj.ipv6_addresses or not options.vlan_interfaces_available:
                blockers.append("TAGGED_PARENT_REQUIRES_NO_NATIVE_ADDRESS_AND_CONFIRMED_VLAN_SUPPORT")
            address = None
        else:
            if not obj.ipv4_addresses or len(obj.ipv4_addresses) != 1 or obj.ipv6_addresses:
                blockers.append("INTERFACE_REQUIRES_ONE_IPV4_ADDRESS_AND_NO_IPV6")
            try:
                address = str(IPv4Interface(obj.ipv4_addresses[0])) if obj.ipv4_addresses else None
            except (ValueError, TypeError):
                address = None
                blockers.append("INTERFACE_IPV4_ADDRESS_INVALID")
        if mapping is None:
            blockers.append("INTERFACE_TARGET_MAPPING_REQUIRED")
        else:
            if tagged_parent and (mapping.unit != 0 or mapping.tag is not None):
                blockers.append("TAGGED_PARENT_REQUIRES_EXPLICIT_PHYSICAL_UNIT_ZERO")
            if obj.vlan and mapping.tag != int(obj.vlan):
                blockers.append("INTERFACE_VLAN_TAG_MAPPING_MISMATCH")
            if mapping.tag and (not options.vlan_interfaces_available or obj.vlan is None):
                blockers.append("VLAN_TARGET_CAPABILITY_OR_SOURCE_TAG_UNVERIFIED")
            settings = {"interface": f"{mapping.target_interface}.{mapping.unit}",
                        "physical_interface": mapping.target_interface, "unit": mapping.unit,
                        "tag": mapping.tag, "address": address, "vlan_trunk": tagged_parent}
        row = _item(obj, "interface", settings.get("interface", _safe_name(obj.name)), settings.items(),
                    blockers=blockers, order=obj.source_order or order)
        result.append(row)
        if obj.name:
            by_source.setdefault(obj.name, []).append(row)
    for order, obj in enumerate([row for row in source.interface_units if _topology_scope(row, selected)
                                 and row.name in member_names]):
        mapping = options.interfaces.get(obj.name or "")
        blockers, settings = [], {}
        if obj.raw_extra or not obj.parent or not obj.tag or not obj.ipv4_addresses or len(obj.ipv4_addresses) != 1 or obj.ipv6_addresses:
            blockers.append("INTERFACE_UNIT_REQUIRES_EXPLICIT_PARENT_TAG_AND_ONE_IPV4")
        parents = by_source.get(obj.parent or "", ())
        if len(parents) != 1:
            blockers.append("INTERFACE_UNIT_PARENT_UNRESOLVED")
        if mapping is None:
            blockers.append("INTERFACE_TARGET_MAPPING_REQUIRED")
        try:
            address = str(IPv4Interface(obj.ipv4_addresses[0])) if obj.ipv4_addresses else None
            tag = int(obj.tag) if obj.tag is not None else None
        except (ValueError, TypeError):
            address, tag = None, None
            blockers.append("INTERFACE_UNIT_ADDRESS_OR_TAG_INVALID")
        if obj.interface_family not in {None, "ethernet"}:
            blockers.append("INTERFACE_UNIT_FAMILY_UNSUPPORTED")
        if mapping and (mapping.tag != tag or not options.vlan_interfaces_available):
            blockers.append("VLAN_TARGET_CAPABILITY_OR_TAG_MISMATCH")
        if mapping and len(parents) == 1:
            parent_values = dict(parents[0].settings)
            if (mapping.target_interface != parent_values.get("physical_interface")
                    or not parent_values.get("vlan_trunk") or mapping.unit == 0):
                blockers.append("INTERFACE_UNIT_PARENT_MAPPING_INCOMPATIBLE")
        if mapping:
            settings = {"interface": f"{mapping.target_interface}.{mapping.unit}",
                        "physical_interface": mapping.target_interface, "unit": mapping.unit,
                        "tag": tag, "address": address}
        row = _item(obj, "interface", settings.get("interface", _safe_name(obj.name)), settings.items(),
                    dependencies=tuple(parent.key for parent in parents), blockers=blockers,
                    order=obj.source_order or order)
        result.append(row)
        if obj.name:
            by_source.setdefault(obj.name, []).append(row)
    return result, by_source


def plan_zones(source, selected, options, interfaces, by_source):
    result, zone_names = [], {}
    for order, zone in enumerate([row for row in source.zones if in_scope(row, selected)]):
        target = options.zones.get(zone.name or "")
        blockers, members, dependencies = [], [], []
        if zone.raw_extra or zone.network_type != "layer3" or not zone.members:
            blockers.append("ZONE_REQUIRES_EXPLICIT_L3_MEMBERS")
        if not target:
            blockers.append("ZONE_TARGET_MAPPING_REQUIRED")
        for member in zone.members or ():
            matches = by_source.get(member, ())
            if len(matches) != 1:
                blockers.append("ZONE_INTERFACE_UNRESOLVED_OR_AMBIGUOUS")
            else:
                members.append(dict(matches[0].settings).get("interface", matches[0].target_name))
                dependencies.append(matches[0].key)
        target = target or _safe_name(zone.name)
        zone_names[zone.name] = target
        result.append(_item(zone, "zone", target, (("interfaces", tuple(members)),), dependencies,
                            blockers, zone.source_order or order))
    for interface in [row for row in source.interfaces if _topology_scope(row, selected) and row.name not in by_source]:
        target = options.interface_zones.get(interface.name or "")
        if not target:
            continue
        row = by_source.get(interface.name or (), ())
        if len(row) != 1:
            continue
        synthetic = _item(interface, "zone", target,
                          (("interfaces", (dict(row[0].settings).get("interface", row[0].target_name),)),),
                          (row[0].key,), blockers=(), order=interface.source_order or 0)
        result.append(synthetic)
    return result, zone_names


def plan_routes(source, selected, by_source, options):
    result = []
    for router in source.virtual_routers:
        if not _topology_scope(router, selected):
            continue
        if router.raw_extra or not router.interfaces or not router.static_routes:
            continue
        for order, route in enumerate(router.static_routes):
            blockers, settings, deps = [], {}, []
            if route.raw_extra or route.address_family != "ipv4" or route.nexthop_type != "ip-address":
                blockers.append("ROUTE_REQUIRES_EXPLICIT_SUPPORTED_IPV4_NEXT_HOP")
            try:
                network = IPv4Network(route.destination, strict=False)
                gateway = IPv4Address(route.nexthop_ip_address)
                if route.metric is None or not 0 <= int(route.metric) <= 4294967295:
                    raise ValueError
                if route.admin_distance is None or not 1 <= int(route.admin_distance) <= 255:
                    raise ValueError
                settings = {"destination": str(network), "gateway": str(gateway),
                            "metric": int(route.metric), "preference": int(route.admin_distance)}
            except (ValueError, TypeError):
                blockers.append("ROUTE_PREFIX_GATEWAY_OR_METRIC_INVALID")
            matches = by_source.get(route.interface or "", ())
            if len(matches) != 1:
                blockers.append("ROUTE_OUTGOING_INTERFACE_UNRESOLVED")
            else:
                deps.append(matches[0].key)
                if not dict(matches[0].settings).get("address"):
                    blockers.append("ROUTE_OUTGOING_INTERFACE_NOT_RENDERABLE")
            result.append(_item(route, "static_route", f"{_safe_name(router.name)}-{_safe_name(route.name)}",
                                settings.items(), deps, blockers, route.source_order or order))
    return result
