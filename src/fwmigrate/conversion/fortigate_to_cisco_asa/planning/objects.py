"""IPv4 address and service objects derived from explicit FortiGate models."""

from ipaddress import ip_address, ip_network

from .naming import item_key, target_name
from ..models import ASAPlanItem


def _ipv4(value):
    parts = str(value or "").split()
    if len(parts) == 1 and "/" in parts[0]:
        network = ip_network(parts[0], strict=False)
    elif len(parts) == 2:
        network = ip_network(f"{parts[0]}/{parts[1]}", strict=False)
    else:
        raise ValueError
    if network.version != 4:
        raise ValueError
    return f"subnet {network.network_address} {network.netmask}"


def plan_objects(source, derived, vdom):
    items, address_names, service_names = [], {}, {}
    addresses = {item.name: item for item in source.addresses if (item.vdom or "root") == vdom and item.address_family == "ipv4"}
    groups = {item.name: item for item in source.address_groups if (item.vdom or "root") == vdom and item.address_family == "ipv4"}
    for address in addresses.values():
        blockers, body = [], []
        try:
            if address.raw_extra:
                blockers.append("ADDRESS_HAS_UNSUPPORTED_SOURCE_SETTINGS")
            if address.type == "ipmask" and {"type", "subnet"} <= address.explicit_fields and address.subnet:
                body = [_ipv4(address.subnet)]
            elif address.type == "iprange" and {"type", "start_ip", "end_ip"} <= address.explicit_fields and address.start_ip and address.end_ip:
                start, end = ip_address(address.start_ip), ip_address(address.end_ip)
                if start.version != 4 or end.version != 4 or int(start) > int(end):
                    raise ValueError
                body = [f"range {start} {end}"]
            else:
                raise ValueError
        except ValueError:
            blockers.append("ADDRESS_REPRESENTATION_UNSUPPORTED")
        name = target_name("address", vdom, address.name)
        address_names[address.name] = name
        commands = (f"object network {name}", *(f" {line}" for line in body)) if body and not blockers else ()
        items.append(ASAPlanItem(item_key(vdom, "address", address.name), "address", vdom, address.name,
                                 name, (("commands", tuple(commands)),), blockers=tuple(blockers)))
    address_names.update({name: target_name("address_group", vdom, name) for name in groups})
    for group in groups.values():
        blockers = []
        members = []
        if group.raw_extra:
            blockers.append("ADDRESS_GROUP_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if "members" not in group.explicit_fields or group.members is None or not group.members:
            blockers.append("ADDRESS_GROUP_MEMBERS_NOT_EXPLICIT_OR_EMPTY")
        if "exclude" not in group.explicit_fields or group.exclude != "disable":
            blockers.append("ADDRESS_GROUP_EXCLUSION_STATE_NOT_EXPLICITLY_DISABLED")
        if group.exclude and group.exclude.casefold() == "enable" or group.exclude_members:
            blockers.append("ADDRESS_GROUP_EXCLUSION_UNSUPPORTED")
        for member in group.members or ():
            if member in address_names:
                syntax = "group-object" if member in groups else "network-object object"
                members.append(f" {syntax} {address_names[member]}")
            else:
                blockers.append("ADDRESS_GROUP_MEMBER_UNRESOLVED")
        name = target_name("address_group", vdom, group.name)
        address_names[group.name] = name
        commands = (f"object-group network {name}", *members) if members and not blockers else ()
        dependencies = tuple(item_key(vdom, "address_group" if member in groups else "address", member)
                             for member in group.members or () if member in address_names or member in groups)
        items.append(ASAPlanItem(item_key(vdom, "address_group", group.name), "address_group", vdom, group.name,
                                 name, (("commands", tuple(commands)),), dependencies,
                                 tuple(dict.fromkeys(blockers))))

    normalized_services = {item.name: item for item in derived.services.services if item.vdom == vdom}
    service_groups = {item.name: item for item in derived.services.groups if item.vdom == vdom}
    raw_services = {item.name: item for item in source.services if (item.vdom or "root") == vdom}
    raw_groups = {item.name: item for item in source.service_groups if (item.vdom or "root") == vdom}
    for name, service in normalized_services.items():
        raw = raw_services.get(service.source_name or name)
        blockers, body = [], []
        proto = (service.protocol or "").casefold()
        active_range = "tcp_portrange" if proto == "tcp" else "udp_portrange"
        if (raw is None or raw.raw_extra or active_range not in raw.explicit_fields
                or proto not in {"tcp", "udp"} or service.source_port):
            blockers.append("SERVICE_PROTOCOL_OR_SOURCE_PORT_UNSUPPORTED")
        if service.port:
            port = str(service.port)
            if "-" in port:
                start, end = port.split("-", 1)
                if not start.isdecimal() or not end.isdecimal() or not 0 <= int(start) <= int(end) <= 65535:
                    blockers.append("SERVICE_PORT_INVALID")
                else:
                    body.append(f" service {proto} destination range {start} {end}")
            elif port.isdecimal() and 0 <= int(port) <= 65535:
                body.append(f" service {proto} destination eq {port}")
            else:
                blockers.append("SERVICE_PORT_UNSUPPORTED")
        else:
            blockers.append("SERVICE_DESTINATION_PORT_NOT_EXPLICIT")
        name_out = target_name("service", vdom, name)
        service_names[name] = name_out
        commands = (f"object service {name_out}", *body) if body and not blockers else ()
        items.append(ASAPlanItem(item_key(vdom, "service", name), "service", vdom, name,
                                 name_out, (("commands", tuple(commands)),), blockers=tuple(blockers)))
    service_names.update({name: target_name("service_group", vdom, name) for name in service_groups})
    for group in service_groups.values():
        members = tuple(group.members or ())
        blockers = ["SERVICE_GROUP_MEMBER_UNRESOLVED"] if not members or any(m not in service_names and m not in service_groups for m in members) else []
        raw_group = raw_groups.get(group.name)
        if not group.generated and (raw_group is None or raw_group.raw_extra
                or "members" not in raw_group.explicit_fields or raw_group.members is None or not raw_group.members):
            blockers.append("SERVICE_GROUP_MEMBERS_NOT_EXPLICIT_OR_UNSUPPORTED")
        if not group.generated and (raw_group is None or "proxy" not in raw_group.explicit_fields
                or raw_group.proxy != "disable"):
            blockers.append("SERVICE_GROUP_PROXY_STATE_NOT_EXPLICITLY_DISABLED")
        name = target_name("service_group", vdom, group.name)
        service_names[group.name] = name
        commands = (f"object-group service {name}", *(f" {'group-object' if m in service_groups else 'service-object object'} {service_names[m]}" for m in members)) if not blockers else ()
        deps = tuple(item_key(vdom, "service_group" if m in service_groups else "service", m) for m in members)
        items.append(ASAPlanItem(item_key(vdom, "service_group", group.name), "service_group", vdom, group.name,
                                 name, (("commands", tuple(commands)),), deps, tuple(blockers)))
    return items, address_names, service_names
