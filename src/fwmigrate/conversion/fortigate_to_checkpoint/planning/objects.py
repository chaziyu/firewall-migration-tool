"""Verified Check Point Management API address and service objects."""

from ipaddress import ip_address, ip_network
import re

from fwmigrate.vendors.fortigate.relationships.references import ReferenceKind

from ..models import CPMigrationItem
from .naming import item_key, target_name


_PORT = re.compile(r"^(\d+)(?:-(\d+))?$")


def _ipv4_network(value):
    parts = str(value or "").split()
    if len(parts) == 1:
        network = ip_network(parts[0], strict=False)
    elif len(parts) == 2:
        network = ip_network(f"{parts[0]}/{parts[1]}", strict=False)
    else:
        raise ValueError
    if network.version != 4:
        raise ValueError
    return network


def _port(value):
    match = _PORT.fullmatch(str(value or ""))
    if not match:
        raise ValueError
    first = int(match.group(1))
    last = int(match.group(2) or first)
    if not 1 <= first <= last <= 65535:
        raise ValueError
    return str(first) if first == last else f"{first}-{last}"


def plan_addresses(source, derived, vdom, context_blockers):
    rows = []
    names = {}
    for order, address in enumerate(source.addresses):
        if (address.vdom or "root") != vdom:
            continue
        blockers = list(context_blockers)
        body = None
        if address.raw_extra or address.associated_interface:
            blockers.append("ADDRESS_HAS_UNSUPPORTED_SOURCE_SETTINGS")
        if address.type != "ipmask" or not {"type", "subnet"} <= set(address.explicit_fields) or not address.subnet:
            blockers.append("ADDRESS_REPRESENTATION_NOT_EXPLICIT_OR_SUPPORTED")
        else:
            try:
                network = _ipv4_network(address.subnet)
                name = target_name("address", vdom, address.name)
                if network.prefixlen == 32:
                    endpoint = "/web_api/add-host"
                    body = {"name": name, "ipv4-address": str(network.network_address)}
                else:
                    endpoint = "/web_api/add-network"
                    body = {"name": name, "subnet4": str(network.network_address), "mask-length4": network.prefixlen}
            except (TypeError, ValueError):
                blockers.append("ADDRESS_REPRESENTATION_NOT_VALID_IPV4")
        name = target_name("address", vdom, address.name)
        duplicated = any(row.kind is ReferenceKind.ADDRESS and row.vdom == vdom and row.name == address.name
                         for row in derived.references.duplicates)
        key = item_key(vdom, "address", f"{address.name}#duplicate:{order}") if duplicated else item_key(vdom, "address", address.name)
        names[address.name] = name
        settings = (("management_operation", {"path": endpoint, "request_body_template": body,
                     "response_binding": {"binding_id": f"{key}.uid", "json_pointer": "/uid", "value_type": "object_uid"}}),) if body else ()
        if duplicated:
            blockers.append("DUPLICATE_SOURCE_ADDRESS")
        rows.append(CPMigrationItem(key, "address", vdom, address.name, name, settings,
                                    blockers=tuple(dict.fromkeys(blockers)), source_order=order))
    return rows, names


def plan_services(source, derived, vdom, context_blockers):
    source_services = {}
    for row in source.services:
        if (row.vdom or "root") == vdom:
            source_services.setdefault(row.name, []).append(row)
    transform_issues = {row.service for row in derived.services.issues if row.vdom == vdom}
    rows, by_source, by_normalized = [], {}, {}
    normalized = [row for row in derived.services.services if row.vdom == vdom]
    for order, service in enumerate(normalized):
        original_rows = source_services.get(service.source_name or service.name, ())
        original = original_rows[0] if len(original_rows) == 1 else None
        source_name = service.source_name or service.name or "unknown"
        normalized_name = service.name or source_name
        duplicated = len(original_rows) > 1 or any(
            row.kind is ReferenceKind.SERVICE and row.vdom == vdom and row.name == source_name
            for row in derived.references.duplicates)
        key = item_key(vdom, "service_leaf", f"{normalized_name}#duplicate:{order}") if duplicated else item_key(vdom, "service_leaf", normalized_name)
        name = target_name("service", vdom, normalized_name)
        blockers = list(context_blockers)
        body = None
        protocol_field = {"tcp": "tcp_portrange", "udp": "udp_portrange"}.get(service.protocol)
        if (original is None or original.raw_extra or source_name in transform_issues
                or len(original_rows) != 1):
            blockers.append("SERVICE_SOURCE_OR_DERIVATION_UNSUPPORTED")
        if service.protocol not in {"tcp", "udp"} or protocol_field is None:
            blockers.append("SERVICE_PROTOCOL_UNSUPPORTED")
        else:
            try:
                if original is None or protocol_field not in set(original.explicit_fields):
                    raise ValueError
                port = _port(service.port)
                body = {"name": name, "port": port}
                if service.source_port is not None:
                    body["source-port"] = _port(service.source_port)
            except (TypeError, ValueError):
                blockers.append("SERVICE_PORT_REPRESENTATION_UNSUPPORTED")
        if body:
            endpoint = f"/web_api/add-service-{service.protocol}"
            settings = (("management_operation", {"path": endpoint, "request_body_template": body,
                         "response_binding": {"binding_id": f"{key}.uid", "json_pointer": "/uid", "value_type": "object_uid"}}),)
        else:
            settings = ()
        if duplicated:
            blockers.append("DUPLICATE_SOURCE_SERVICE")
            settings = ()
        rows.append(CPMigrationItem(key, "service", vdom, source_name, name, settings,
                                    blockers=tuple(dict.fromkeys(blockers)), source_order=order))
        leaf = (name, key)
        by_source.setdefault(source_name, []).append(leaf)
        by_normalized.setdefault(normalized_name, []).append(leaf)
    return rows, by_source, by_normalized


def address_leaves(source, derived, vdom, name, path=()):
    if name.casefold() == "all":
        return [("Any", None)]
    if name in path:
        raise ValueError("ADDRESS_GROUP_CYCLE")
    address = derived.references.get(ReferenceKind.ADDRESS, vdom=vdom, name=name)
    if any(row.kind is ReferenceKind.ADDRESS and row.vdom == vdom and row.name == name
           for row in derived.references.duplicates):
        raise ValueError("DUPLICATE_SOURCE_ADDRESS")
    group = derived.references.get(ReferenceKind.ADDRESS_GROUP, vdom=vdom, name=name)
    if address is not None and group is not None:
        raise ValueError("ADDRESS_REFERENCE_AMBIGUOUS")
    if address is not None:
        return [(target_name("address", vdom, name), item_key(vdom, "address", name))]
    if group is None:
        if name.casefold() == "all6":
            raise ValueError("IPV6_ADDRESS_PREDEFINED_UNSUPPORTED")
        raise ValueError("ADDRESS_REFERENCE_UNRESOLVED")
    if any(row.kind is ReferenceKind.ADDRESS_GROUP and row.vdom == vdom and row.name == name
           for row in derived.references.duplicates):
        raise ValueError("DUPLICATE_SOURCE_ADDRESS_GROUP")
    if group.address_family != "ipv4" or group.exclude or group.exclude_members or not group.members:
        raise ValueError("ADDRESS_GROUP_SEMANTICS_UNSUPPORTED")
    result = []
    for member in group.members:
        result.extend(address_leaves(source, derived, vdom, member, (*path, name)))
    return result


def service_leaves(source, derived, vdom, name, by_source, by_normalized, path=()):
    if name.casefold() == "all":
        return [("Any", None)]
    if name in path:
        raise ValueError("SERVICE_GROUP_CYCLE")
    service = derived.references.get(ReferenceKind.SERVICE, vdom=vdom, name=name)
    if any(row.kind is ReferenceKind.SERVICE and row.vdom == vdom and row.name == name
           for row in derived.references.duplicates):
        raise ValueError("DUPLICATE_SOURCE_SERVICE")
    group = derived.references.get(ReferenceKind.SERVICE_GROUP, vdom=vdom, name=name)
    if service is not None and group is not None:
        raise ValueError("SERVICE_REFERENCE_AMBIGUOUS")
    generated_groups = {row.name: row for row in derived.services.groups if row.vdom == vdom and row.generated}
    generated = generated_groups.get(name)
    if generated is not None:
        if group is not None:
            raise ValueError("SERVICE_REFERENCE_AMBIGUOUS")
        if not generated.members:
            raise ValueError("GENERATED_SERVICE_GROUP_MEMBERSHIP_UNKNOWN")
        result = []
        for member in generated.members or ():
            result.extend(service_leaves(source, derived, vdom, member, by_source, by_normalized, (*path, name)))
        return result
    normalized = by_normalized.get(name)
    if normalized:
        return list(normalized)
    if service is not None:
        rows = by_source.get(name, ())
        if not rows:
            raise ValueError("SERVICE_REPRESENTATION_UNSUPPORTED")
        return list(rows)
    if group is None:
        raise ValueError("SERVICE_REFERENCE_UNRESOLVED")
    if any(row.kind is ReferenceKind.SERVICE_GROUP and row.vdom == vdom and row.name == name
           for row in derived.references.duplicates):
        raise ValueError("DUPLICATE_SOURCE_SERVICE_GROUP")
    if not group.members:
        raise ValueError("SERVICE_GROUP_MEMBERSHIP_UNKNOWN")
    result = []
    for member in group.members:
        result.extend(service_leaves(source, derived, vdom, member, by_source, by_normalized, (*path, name)))
    return result

