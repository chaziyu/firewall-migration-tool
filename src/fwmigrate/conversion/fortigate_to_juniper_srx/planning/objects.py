"""FortiGate address and service objects planned as Juniper SRX objects."""

from ipaddress import IPv4Address, IPv4Network
import re

from fwmigrate.vendors.fortigate.relationships.references import ReferenceKind

from ..models import SRXPlanItem
from .naming import item_key, target_name


def _make_item(vdom, family, name, settings=(), dependencies=(), blockers=(), order=0):
    return SRXPlanItem(
        key=item_key(vdom, family, name),
        family=family,
        source_vdom=vdom,
        source_name=name,
        target_name=target_name(family, vdom, name),
        settings=tuple(settings),
        dependencies=tuple(dict.fromkeys(dependencies)),
        blockers=tuple(dict.fromkeys(blockers)),
        source_order=order,
    )


def _ipv4_address(address):
    try:
        return str(IPv4Address(address))
    except (ValueError, TypeError):
        return None


def _address_values(address):
    if address.address_family != "ipv4":
        return None, "IPV6_ADDRESS_UNSUPPORTED"
    if address.raw_extra or address.associated_interface or address.wildcard or address.wildcard_fqdn:
        return None, "ADDRESS_HAS_UNSUPPORTED_SOURCE_SETTINGS"
    if address.type == "ipmask" and {"type", "subnet"} <= address.explicit_fields and address.subnet:
        parts = address.subnet.split()
        if len(parts) != 2:
            return None, "ADDRESS_SUBNET_IS_NOT_AN_EXPLICIT_IPV4_ADDRESS_AND_MASK"
        try:
            network = IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
        except ValueError:
            return None, "ADDRESS_SUBNET_IS_NOT_VALID_IPV4"
        return {"address_type": "prefix", "value": str(network)}, None
    if address.type == "iprange" and {"type", "start_ip", "end_ip"} <= address.explicit_fields:
        start, end = _ipv4_address(address.start_ip), _ipv4_address(address.end_ip)
        if start is None or end is None or int(IPv4Address(start)) > int(IPv4Address(end)):
            return None, "ADDRESS_RANGE_IS_NOT_VALID_IPV4"
        return {"address_type": "range", "range_start": start, "range_end": end}, None
    if "fqdn" in address.explicit_fields:
        return None, "FQDN_RUNTIME_SEMANTICS_UNVERIFIED"
    return None, "ADDRESS_REPRESENTATION_NOT_EXPLICIT_OR_SUPPORTED"


def _reference(derived, vdom, name):
    return derived.references.resolve_any(
        vdom=vdom,
        name=name,
        kinds=(ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP),
    )


def plan_address_objects(source, derived, vdom):
    addresses = [item for item in source.addresses if item.vdom == vdom]
    groups = [item for item in source.address_groups if item.vdom == vdom]
    address_items = {}
    group_items = {}
    for order, address in enumerate(addresses):
        values, issue = _address_values(address)
        blockers = [issue] if issue else []
        if any(row.kind is ReferenceKind.ADDRESS and row.vdom == vdom and row.name == address.name
               for row in derived.references.duplicates):
            blockers.append("DUPLICATE_SOURCE_ADDRESS")
        item = _make_item(vdom, "address", address.name, (values or {}).items(), blockers=blockers, order=order)
        address_items[address.name] = item
    for order, group in enumerate(groups):
        blockers = []
        if group.address_family != "ipv4":
            blockers.append("IPV6_ADDRESS_GROUP_UNSUPPORTED")
        if group.raw_extra or group.exclude or group.exclude_members:
            blockers.append("ADDRESS_GROUP_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if group.members is None:
            blockers.append("ADDRESS_GROUP_MEMBERS_NOT_EXPLICIT")
        if any(row.kind is ReferenceKind.ADDRESS_GROUP and row.vdom == vdom and row.name == group.name
               for row in derived.references.duplicates):
            blockers.append("DUPLICATE_SOURCE_ADDRESS_GROUP")
        item = _make_item(vdom, "address_group", group.name, blockers=blockers, order=order)
        group_items[group.name] = item

    group_by_name = {item.name: item for item in groups}

    def member_plan(group_name, stack):
        if group_name in stack:
            return (), (), ("ADDRESS_GROUP_CYCLE",)
        group = group_by_name[group_name]
        if group.members is None:
            return (), (), ("ADDRESS_GROUP_MEMBERS_NOT_EXPLICIT",)
        members, dependencies, blockers = [], [], []
        next_stack = (*stack, group_name)
        for name in group.members:
            reference = _reference(derived, vdom, name)
            if reference is None or reference.predefined:
                blockers.append("ADDRESS_GROUP_MEMBER_UNRESOLVED_OR_PREDEFINED")
                continue
            if reference.kind is ReferenceKind.ADDRESS:
                member = address_items.get(name)
                if member is None:
                    blockers.append("ADDRESS_GROUP_MEMBER_OUTSIDE_SELECTED_SCOPE")
                    continue
                members.append(member.target_name)
                dependencies.append(member.key)
                if member.blockers:
                    blockers.append("ADDRESS_GROUP_MEMBER_BLOCKED")
            elif reference.kind is ReferenceKind.ADDRESS_GROUP:
                member = group_items.get(name)
                if member is None:
                    blockers.append("ADDRESS_GROUP_MEMBER_OUTSIDE_SELECTED_SCOPE")
                    continue
                nested_members, nested_dependencies, nested_blockers = member_plan(name, next_stack)
                members.append(member.target_name)
                dependencies.append(member.key)
                dependencies.extend(nested_dependencies)
                blockers.extend(nested_blockers)
        return tuple(members), tuple(dependencies), tuple(dict.fromkeys(blockers))

    for order, group in enumerate(groups):
        item = group_items[group.name]
        members, dependencies, member_blockers = member_plan(group.name, ())
        blockers = (*item.blockers, *member_blockers)
        if not members:
            blockers = (*blockers, "ADDRESS_GROUP_EMPTY")
        group_items[group.name] = _make_item(
            vdom, "address_group", group.name,
            (("members", members),) if members else (), dependencies,
            blockers, order,
        )
    return [*address_items.values(), *group_items.values()]


def plan_service_objects(source, derived, vdom):
    items = []
    service_targets = {}
    for order, service in enumerate(derived.services.services):
        if service.vdom != vdom:
            continue
        blockers = []
        if service.protocol not in {"tcp", "udp"}:
            blockers.append("SERVICE_PROTOCOL_UNSUPPORTED")
        if not service.port:
            blockers.append("SERVICE_DESTINATION_PORT_NOT_EXPLICIT")
        for port in (service.port, service.source_port):
            if port is not None and not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", port):
                blockers.append("SERVICE_PORT_FORMAT_UNSUPPORTED")
                continue
            if port is not None:
                bounds = tuple(map(int, port.split("-")))
                if any(value < 1 or value > 65535 for value in bounds) or (len(bounds) == 2 and bounds[0] > bounds[1]):
                    blockers.append("SERVICE_PORT_RANGE_INVALID")
        if any(issue.vdom == vdom and issue.service == (service.source_name or service.name)
               for issue in derived.services.issues):
            blockers.append("SERVICE_SOURCE_SETTINGS_UNSUPPORTED")
        source_item = next((item for item in source.services if item.vdom == vdom and item.name == service.source_name), None)
        if source_item is not None and (source_item.raw_extra or source_item.proxy):
            blockers.append("SERVICE_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        item = _make_item(
            vdom, "service", service.name,
            (("protocol", service.protocol), ("destination_port", service.port),
             ("source_port", service.source_port)),
            blockers=blockers,
            order=order,
        )
        items.append(item)
        service_targets[service.name] = item
    group_items = []
    derived_groups = [group for group in derived.services.groups if group.vdom == vdom]
    groups_by_name = {group.name: group for group in derived_groups}
    source_groups = {group.name: group for group in source.service_groups if group.vdom == vdom}

    def group_members(name, stack):
        if name in stack:
            return (), (), ("SERVICE_GROUP_CYCLE",)
        group = groups_by_name[name]
        if group.members is None:
            return (), (), ("SERVICE_GROUP_MEMBERS_NOT_EXPLICIT",)
        members, dependencies, blockers = [], [], []
        for child_name in group.members:
            child = service_targets.get(child_name)
            if child is not None:
                members.append(child.target_name)
                dependencies.append(child.key)
                if child.blockers:
                    blockers.append("SERVICE_GROUP_MEMBER_BLOCKED")
                continue
            nested = groups_by_name.get(child_name)
            if nested is None:
                blockers.append("SERVICE_GROUP_MEMBER_UNRESOLVED")
                continue
            nested_members, nested_dependencies, nested_blockers = group_members(child_name, (*stack, name))
            members.extend(nested_members)
            dependencies.extend(nested_dependencies)
            blockers.extend(nested_blockers)
        return tuple(dict.fromkeys(members)), tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(blockers))

    for order, group in enumerate(derived_groups):
        members, dependencies, blockers = group_members(group.name, ())
        source_group = source_groups.get(group.name)
        if source_group is not None and (source_group.proxy or source_group.raw_extra):
            blockers = (*blockers, "SERVICE_GROUP_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if not members:
            blockers = (*blockers, "SERVICE_GROUP_EMPTY_OR_UNRESOLVED")
        group_items.append(_make_item(
            vdom, "service_group", group.name, (("members", members),) if members else (),
            dependencies, blockers, order,
        ))
    return [*items, *group_items]


def plan_objects(source, derived, vdom):
    return [*plan_address_objects(source, derived, vdom), *plan_service_objects(source, derived, vdom)]
