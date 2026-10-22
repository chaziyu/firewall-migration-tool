"""Routed single-context ASA interfaces and explicit static routes."""

from ipaddress import ip_address, ip_interface, ip_network
import re

from .naming import item_key, target_name
from ..models import ASAPlanItem


def plan_topology(source, options):
    items = []
    names = {}
    for interface in source.interfaces:
        vdom = interface.vdom or "root"
        if vdom != options.source_vdom:
            continue
        mapping = options.interfaces.get(vdom, {}).get(interface.name)
        blockers = []
        dependencies = ()
        is_vlan = interface.type == "vlan" and "type" in interface.explicit_fields
        if mapping is None:
            blockers.append("TARGET_INTERFACE_MAPPING_REQUIRED")
        if not is_vlan and (interface.type not in {"physical", "ethernet"} or "type" not in interface.explicit_fields):
            blockers.append("INTERFACE_TYPE_NOT_EXPLICITLY_PHYSICAL")
        if (interface.interface and not is_vlan) or interface.members:
            blockers.append("INTERFACE_TOPOLOGY_UNSUPPORTED")
        if is_vlan:
            if interface.explicit_fields - {"type", "interface", "vlanid", "ip", "status", "mode", "vdom", "description", "alias"}:
                blockers.append("VLAN_HAS_UNSUPPORTED_SOURCE_SETTINGS")
            if options.target_platform != "asav" or not options.vlan_interfaces_available:
                blockers.append("VLAN_ASAV_PLATFORM_AND_AVAILABILITY_REQUIRED")
            parents = [row for row in source.interfaces if (row.vdom or "root") == vdom and row.name == interface.interface]
            parent = parents[0] if len(parents) == 1 else None
            parent_mapping = options.interfaces.get(vdom, {}).get(interface.interface)
            if (parent is None or parent.type not in {"physical", "ethernet"}
                    or parent.interface or parent.members or parent_mapping is None
                    or parent.explicit_fields - {"type", "ip", "status", "mode", "vdom", "description", "alias"}):
                blockers.append("VLAN_PHYSICAL_PARENT_MAPPING_REQUIRED")
            else:
                dependencies = (item_key(vdom, "interface", parent.name),)
                suffix = mapping.interface.removeprefix(parent_mapping.interface + ".") if mapping else ""
                if (not re.fullmatch(r"GigabitEthernet\d+/\d+", parent_mapping.interface)
                        or mapping is None or mapping.interface != parent_mapping.interface + "." + suffix
                        or not suffix.isdigit() or not 1 <= int(suffix) <= 4294967293):
                    blockers.append("VLAN_TARGET_SUBINTERFACE_PARENT_INVALID")
            if ("vlanid" not in interface.explicit_fields or type(interface.vlanid) is not int
                    or not 1 <= interface.vlanid <= 4094):
                blockers.append("VLAN_ID_NOT_EXPLICIT_OR_VALID")
            if sum(row.vdom == interface.vdom and row.type == "vlan" and row.vlanid == interface.vlanid
                   for row in source.interfaces) != 1:
                blockers.append("VLAN_TAG_OWNERSHIP_AMBIGUOUS")
        if mapping and any(name != interface.name and
                (row.interface.casefold() == mapping.interface.casefold() or row.nameif.casefold() == mapping.nameif.casefold())
                for name, row in options.interfaces.get(vdom, {}).items()):
            blockers.append("TARGET_INTERFACE_OWNERSHIP_AMBIGUOUS")
        if interface.raw_extra:
            blockers.append("INTERFACE_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if "status" not in interface.explicit_fields or interface.status not in {"up", "down"}:
            blockers.append("INTERFACE_STATUS_NOT_EXPLICIT")
        if interface.mode is not None and interface.mode.casefold() != "static":
            blockers.append("INTERFACE_ADDRESSING_MODE_UNSUPPORTED")
        settings = {"source_interface": interface.name}
        commands = []
        target = ""
        if mapping:
            names[interface.name] = mapping.nameif
            target = mapping.nameif
            commands = [f"interface {mapping.interface}", f" nameif {mapping.nameif}",
                        f" security-level {mapping.security_level}"]
            if is_vlan:
                commands.insert(1, f" vlan {interface.vlanid}")
            if "ip" not in interface.explicit_fields or not interface.ip:
                blockers.append("INTERFACE_IPV4_ADDRESS_NOT_EXPLICIT")
            else:
                try:
                    parts = str(interface.ip).split()
                    address = ip_interface(f"{parts[0]}/{parts[1]}") if len(parts) == 2 else ip_interface(parts[0])
                    if address.version != 4:
                        raise ValueError
                    commands.append(f" ip address {address.ip} {address.network.netmask}")
                except ValueError:
                    blockers.append("SOURCE_INTERFACE_ADDRESS_UNSUPPORTED")
            if interface.status == "up":
                commands.append(" no shutdown")
            elif interface.status == "down":
                commands.append(" shutdown")
        if blockers:
            commands = []
        settings["commands"] = tuple(commands)
        if is_vlan:
            settings.update(vlan_id=interface.vlanid, parent_interface=interface.interface)
        key = item_key(vdom, "interface", interface.name)
        items.append(ASAPlanItem(key, "interface", vdom, interface.name, target,
                                 tuple(settings.items()), dependencies=dependencies, blockers=tuple(dict.fromkeys(blockers))))

    interface_keys = {item.key for item in items}
    for route in source.static_routes:
        vdom = route.vdom or "root"
        if vdom != options.source_vdom:
            continue
        blockers = []
        destination = route.dst or route.dstaddr
        required_fields = {"dst", "device", "gateway", "distance", "priority", "status"}
        if (route.address_family != "ipv4" or required_fields - route.explicit_fields
                or route.dstaddr or not destination or not route.device or not route.gateway
                or route.distance is None or route.priority != 0 or route.status != "enable"):
            blockers.append("STATIC_ROUTE_EXPLICIT_IPV4_FIELDS_REQUIRED")
        if route.raw_extra:
            blockers.append("STATIC_ROUTE_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if route.dynamic_gateway or route.blackhole not in (None, "disable") or route.vrf not in (None, 0) or route.sdwan_zone or route.src or route.preferred_source or route.priority not in (None, 0):
            blockers.append("STATIC_ROUTE_FORWARDING_BEHAVIOR_UNSUPPORTED")
        nameif = names.get(route.device)
        if not nameif:
            blockers.append("STATIC_ROUTE_INTERFACE_MAPPING_REQUIRED")
        command = None
        try:
            parts = str(destination).split()
            network = ip_network(f"{parts[0]}/{parts[1]}", strict=False) if len(parts) == 2 else ip_network(destination, strict=False)
            gateway = ip_address(route.gateway)
            if network.version != 4 or gateway.version != 4:
                raise ValueError
            distance = f" {route.distance}" if route.distance is not None else ""
            command = f"route {nameif} {network.network_address} {network.netmask} {gateway}{distance}"
        except ValueError:
            blockers.append("STATIC_ROUTE_INVALID_IPV4_VALUE")
        settings = (("commands", (command,) if command and not blockers else ()),)
        items.append(ASAPlanItem(item_key(vdom, "static_route", str(route.seq_num or destination)),
                                 "static_route", vdom, str(route.seq_num or destination),
                                 target_name("static_route", vdom, str(route.seq_num or destination)),
                                 settings, (item_key(vdom, "interface", route.device),)
                                 if item_key(vdom, "interface", route.device) in interface_keys else (),
                                 tuple(dict.fromkeys(blockers)), int(route.seq_num or 0)))
    return items, names
