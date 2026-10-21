"""Plan bounded PAN-OS IPv4 address and transport application objects."""

from ipaddress import IPv4Address, IPv4Network
import re

from .source_scope import identity, in_scope
from ..models import SRXPlanItem


def _safe_name(value):
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "")[:63].strip("_.-")
    return value or "unnamed"


def _item(obj, family, name, settings=(), dependencies=(), blockers=(), order=0):
    return SRXPlanItem(
        identity(obj, family), family, identity(obj, "scope"), family, obj.name or "(unnamed)",
        obj.source_path, name, tuple(settings), tuple(dict.fromkeys(dependencies)),
        tuple(dict.fromkeys(blockers)), order,
    )


def plan_addresses(source, selected):
    result, refs = [], {}
    objects = [item for item in source.addresses if in_scope(item, selected)]
    groups = [item for item in source.address_groups if in_scope(item, selected)]
    for order, obj in enumerate(objects):
        name = _safe_name(obj.name)
        blockers, settings = [], {}
        if obj.raw_extra or obj.fqdn or obj.ip_wildcard or len(obj.explicit_fields & {"ip_netmask", "ip_range", "fqdn", "ip_wildcard"}) != 1:
            blockers.append("ADDRESS_REPRESENTATION_NOT_EXPLICIT_OR_SUPPORTED")
        try:
            if obj.ip_netmask:
                network = IPv4Network(obj.ip_netmask, strict=False)
                settings = {"address_type": "prefix", "value": str(network)}
            elif obj.ip_range:
                start, end = (IPv4Address(part.strip()) for part in obj.ip_range.split("-", 1))
                if int(start) > int(end):
                    raise ValueError
                settings = {"address_type": "range", "range_start": str(start), "range_end": str(end)}
            else:
                raise ValueError
        except (ValueError, TypeError):
            blockers.append("ADDRESS_VALUE_INVALID")
        row = _item(obj, "address", name, settings.items(), blockers=blockers, order=obj.source_order or order)
        result.append(row)
        if obj.name:
            refs.setdefault(obj.name, []).append(row)
    for order, obj in enumerate(groups):
        name = _safe_name(obj.name)
        members, dependencies, blockers = [], [], []
        if obj.raw_extra or obj.dynamic_filter or not obj.static_members:
            blockers.append("ADDRESS_GROUP_MUST_BE_STATIC_AND_EXPLICIT")
        for member in obj.static_members or ():
            matches = refs.get(member, ())
            if len(matches) != 1:
                blockers.append("ADDRESS_GROUP_MEMBER_UNRESOLVED_OR_AMBIGUOUS")
            else:
                members.append(matches[0].target_name)
                dependencies.append(matches[0].key)
        row = _item(obj, "address_group", name, (("members", tuple(members)),), dependencies,
                    blockers, obj.source_order or order)
        result.append(row)
        if obj.name:
            refs.setdefault(obj.name, []).append(row)
    return result


def _ports(value):
    if not isinstance(value, str):
        raise ValueError
    values = []
    for entry in value.split(","):
        parts = entry.strip().split("-")
        if len(parts) not in {1, 2} or any(not part.isdecimal() for part in parts):
            raise ValueError
        low, high = int(parts[0]), int(parts[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError
        values.append(str(low) if low == high else f"{low}-{high}")
    if not values:
        raise ValueError
    return tuple(values)


def plan_services(source, selected):
    result, refs = [], {}
    services = [item for item in source.services if in_scope(item, selected)]
    groups = [item for item in source.service_groups if in_scope(item, selected)]
    for order, obj in enumerate(services):
        blockers, settings = [], {}
        if obj.raw_extra or (obj.tcp is None) == (obj.udp is None):
            blockers.append("SERVICE_SOURCE_OR_PROTOCOL_UNSUPPORTED")
        branch = obj.tcp or obj.udp
        if branch and (branch.raw_extra or branch.override):
            blockers.append("SERVICE_OVERRIDE_OR_UNKNOWN_SETTINGS_UNSUPPORTED")
        try:
            settings = {"protocol": "tcp" if obj.tcp else "udp", "destination_ports": _ports(branch.port)}
            if branch.source_port:
                settings["source_ports"] = _ports(branch.source_port)
        except (ValueError, TypeError, AttributeError):
            blockers.append("SERVICE_PORTS_INVALID_OR_UNSUPPORTED")
        row = _item(obj, "service", _safe_name(obj.name), settings.items(), blockers=blockers,
                    order=obj.source_order or order)
        result.append(row)
        if obj.name:
            refs.setdefault(obj.name, []).append(row)
    for order, obj in enumerate(groups):
        members, dependencies, blockers = [], [], []
        if obj.raw_extra or not obj.members:
            blockers.append("SERVICE_GROUP_MUST_BE_EXPLICIT")
        for member in obj.members or ():
            matches = refs.get(member, ())
            if len(matches) != 1:
                blockers.append("SERVICE_GROUP_MEMBER_UNRESOLVED_OR_AMBIGUOUS")
            else:
                members.append(matches[0].target_name)
                dependencies.append(matches[0].key)
        row = _item(obj, "service_group", _safe_name(obj.name), (("members", tuple(members)),),
                    dependencies, blockers, obj.source_order or order)
        result.append(row)
        if obj.name:
            refs.setdefault(obj.name, []).append(row)
    return result
