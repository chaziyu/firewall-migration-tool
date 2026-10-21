"""Native PAN objects to bounded Check Point Management API creation requests."""

from ipaddress import IPv4Address, IPv4Network
from itertools import product

from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity

from ..models import CPMigrationItem
from .naming import target_name
from .source_scope import identity, in_scope


def operation(key, path, body, value_type="object_uid"):
    return ("management_operation", {"path": "/web_api/" + path,
        "request_body_template": {**body, "details-level": "full"},
        "response_binding": {"binding_id": key + ".uid", "json_pointer": "/uid", "value_type": value_type}})


def item(obj, family, *, settings=(), dependencies=(), blockers=(), suffix="", name=None, order=None):
    scope = pan_scope_identity(obj.scope) if obj.scope else "unscoped"
    return CPMigrationItem(identity(obj, family) + suffix, family, scope, obj.name or "(unnamed)",
        name or target_name(family, scope, (obj.name or "unnamed") + suffix), tuple(settings),
        tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(blockers)),
        (obj.source_order or 0) if order is None else order, source_path=obj.source_path,
        source_kind=type(obj).__name__)


def binding(key):
    return {"$response_binding": key + ".uid"}


def _ports(value):
    if not isinstance(value, str):
        raise ValueError("SERVICE_PORTS_MUST_BE_EXPLICIT")
    result = []
    for token in value.split(","):
        parts = token.strip().split("-")
        if len(parts) not in {1, 2} or any(not part.isdecimal() for part in parts):
            raise ValueError("SERVICE_PORTS_INVALID")
        low, high = int(parts[0]), int(parts[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError("SERVICE_PORTS_INVALID")
        result.append(str(low) if low == high else f"{low}-{high}")
    return tuple(dict.fromkeys(result))


def _groups(source_rows, family, refs):
    result = []
    for obj in source_rows:
        refs.setdefault(obj.name, []).append(item(obj, family))
    for obj in source_rows:
        members = obj.static_members if family == "address_group" else obj.members
        deps, blockers = [], []
        if obj.raw_extra or not members or getattr(obj, "dynamic_filter", None):
            blockers.append("GROUP_MEMBERSHIP_MUST_BE_STATIC_AND_EXPLICIT")
        for name in members or ():
            matches = refs.get(name, ())
            if len(matches) != 1:
                blockers.append("GROUP_MEMBER_UNRESOLVED_OR_AMBIGUOUS")
            else:
                deps.append(matches[0].key)
        row = item(obj, family, dependencies=deps, blockers=blockers)
        path = "add-group" if family == "address_group" else "add-service-group"
        result.append(item(obj, family, dependencies=deps, blockers=blockers,
            settings=(operation(row.key, path, {"name": row.target_name, "members": [binding(key) for key in deps]}),)))
    return result


def plan_addresses(source, selected):
    result, refs = [], {}
    for obj in (obj for obj in source.addresses if in_scope(obj, selected)):
        row = item(obj, "address")
        blockers, path, body = [], "add-host", {}
        if (obj.raw_extra or obj.fqdn or obj.ip_wildcard
                or len(obj.explicit_fields & {"ip_netmask", "ip_range", "fqdn", "ip_wildcard"}) != 1):
            blockers.append("ADDRESS_REPRESENTATION_UNSUPPORTED")
        try:
            if obj.ip_netmask:
                prefix = IPv4Network(obj.ip_netmask, strict=False)
                if prefix.prefixlen == 32:
                    body = {"ipv4-address": str(prefix.network_address)}
                else:
                    path, body = "add-network", {"subnet4": str(prefix.network_address), "mask-length4": prefix.prefixlen}
            elif obj.ip_range:
                low, high = (IPv4Address(value.strip()) for value in obj.ip_range.split("-", 1))
                if low > high:
                    raise ValueError
                path, body = "add-address-range", {"ipv4-address-first": str(low), "ipv4-address-last": str(high)}
            else:
                raise ValueError
        except (ValueError, TypeError):
            blockers.append("ADDRESS_VALUE_UNSUPPORTED")
        row = item(obj, "address", blockers=blockers, settings=(operation(row.key, path,
            {"name": row.target_name, **body, "nat-settings": {"auto-rule": False}}),))
        result.append(row)
        refs.setdefault(obj.name, []).append(row)
    result.extend(_groups([obj for obj in source.address_groups if in_scope(obj, selected)], "address_group", refs))
    return result


def plan_services(source, selected):
    result, refs = [], {}
    for obj in (obj for obj in source.services if in_scope(obj, selected)):
        row = item(obj, "service_group")
        blockers, leaves = [], []
        try:
            if obj.raw_extra or (obj.tcp is None) == (obj.udp is None):
                raise ValueError("SERVICE_PROTOCOL_OR_SETTINGS_UNSUPPORTED")
            branch = obj.tcp or obj.udp
            if branch.raw_extra or branch.override:
                raise ValueError("SERVICE_OVERRIDE_OR_UNKNOWN_SETTINGS_UNSUPPORTED")
            sources, destinations = _ports(branch.source_port), _ports(branch.port)
            if len(sources) * len(destinations) > 256:
                raise ValueError("SERVICE_EXPANSION_LIMIT")
            protocol = "tcp" if obj.tcp else "udp"
            for index, (src, dst) in enumerate(product(sources, destinations)):
                leaf = item(obj, "service", suffix=f":{index}")
                leaves.append(item(obj, "service", suffix=f":{index}", settings=(operation(leaf.key,
                    "add-service-" + protocol, {"name": leaf.target_name, "source-port": src, "port": dst,
                        "match-for-any": False, "match-by-protocol-signature": False}),)))
        except ValueError as exc:
            blockers.append(str(exc))
        deps = tuple(leaf.key for leaf in leaves)
        result.extend(leaves)
        row = item(obj, "service_group", blockers=blockers, dependencies=deps, settings=(operation(row.key,
            "add-service-group", {"name": row.target_name, "members": [binding(key) for key in deps]}),))
        result.append(row)
        refs.setdefault(obj.name, []).append(row)
    result.extend(_groups([obj for obj in source.service_groups if in_scope(obj, selected)], "service_group", refs))
    return result
